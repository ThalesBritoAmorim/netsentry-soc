import React, { useState } from 'react';
import { ThreatAlert } from '../types';
import { 
  X, 
  ShieldCheck, 
  RotateCcw, 
  Copy, 
  Check, 
  Terminal, 
  AlertTriangle, 
  ExternalLink,
  ShieldAlert,
  Zap,
  Play,
  Bot,
  Sparkles
} from 'lucide-react';
import { aiService } from '../services/aiService';

interface MitigationModalProps {
  alert: ThreatAlert | null;
  onClose: () => void;
  onApplyMitigation: (alertId: string) => void;
  onRollbackMitigation: (alertId: string) => void;
  onOpenKaliTerminal?: (cmd: string) => void;
}

export const MitigationModal: React.FC<MitigationModalProps> = ({
  alert,
  onClose,
  onApplyMitigation,
  onRollbackMitigation,
  onOpenKaliTerminal
}) => {
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [isAuditing, setIsAuditing] = useState(false);
  const [auditResult, setAuditResult] = useState<{
    isValid: boolean;
    safetyScore: number;
    risks: string[];
    improvements: string;
    safeAlternative: string;
  } | null>(null);

  const pb = alert?.playbook;

  const handleAuditRule = async () => {
    if (!pb) return;
    setIsAuditing(true);
    try {
      const res = await aiService.auditIptablesRule(pb.iptablesCommand);
      setAuditResult(res);
    } finally {
      setIsAuditing(false);
    }
  };

  if (!alert || !pb) return null;

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-fadeIn">
      <div className="relative w-full max-w-3xl bg-slate-900 border border-slate-800 rounded-xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between bg-slate-950/50">
          <div className="flex items-center gap-3">
            <div className={`p-2 rounded-lg ${
              alert.severity === 'critical' ? 'bg-rose-950/70 text-rose-400 border border-rose-800' :
              alert.severity === 'high' ? 'bg-amber-950/70 text-amber-400 border border-amber-800' :
              'bg-cyan-950/70 text-cyan-400 border border-cyan-800'
            }`}>
              <ShieldAlert className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-base font-semibold text-slate-100 flex items-center gap-2">
                {alert.title}
              </h2>
              <div className="flex items-center gap-2 text-xs text-slate-400 mt-0.5">
                <span className="font-mono text-slate-300">{alert.sourceIp}</span>
                <span aria-hidden="true">·</span>
                <span>Gravidade: <span className="uppercase font-medium text-slate-200">{alert.severity}</span></span>
                <span aria-hidden="true">·</span>
                <span>Confiança: <span className="font-mono tabular-nums text-slate-200">{alert.confidence}%</span></span>
              </div>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 text-slate-400 hover:text-slate-100 rounded-lg hover:bg-slate-800 transition-colors"
            aria-label="Fechar modal"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content Body */}
        <div className="p-6 overflow-y-auto space-y-6 text-sm text-slate-300">
          {/* Anomaly & Vulnerability Analysis */}
          <div className="bg-slate-950/60 p-4 rounded-lg border border-slate-800 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                Diagnóstico Autônomo & Evidências
              </span>
              {alert.mitreAttack && (
                <span className="text-xs font-mono text-cyan-400">
                  MITRE {alert.mitreAttack}
                </span>
              )}
            </div>
            <p className="text-slate-300 leading-relaxed">
              {alert.details}
            </p>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-2 border-t border-slate-800/80 text-xs">
              <div>
                <span className="text-slate-500 block">IP de Origem</span>
                <span className="font-mono text-slate-200">{alert.sourceIp}</span>
              </div>
              <div>
                <span className="text-slate-500 block">MAC de Origem</span>
                <span className="font-mono text-slate-200">{alert.sourceMac || 'N/A'}</span>
              </div>
              <div>
                <span className="text-slate-500 block">Alvo / Vítima</span>
                <span className="font-mono text-slate-200">{alert.targetIp}</span>
              </div>
              <div>
                <span className="text-slate-500 block">Protocolo</span>
                <span className="font-mono text-slate-200">{alert.protocol}</span>
              </div>
            </div>
          </div>

          {/* Suggested Remediation Plan */}
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                Ação de Mitigação Sugerida (Playbook)
              </span>
              <span className="text-xs text-slate-400">
                Status: {pb.applied ? (
                  <span className="text-emerald-400 font-semibold">Mitigado com Sucesso</span>
                ) : (
                  <span className="text-amber-400 font-semibold">Pendente de Aplicação</span>
                )}
              </span>
            </div>
            <div className="p-3.5 bg-slate-950/80 rounded-lg border border-slate-800">
              <p className="font-medium text-slate-100">{pb.actionName}</p>
              <p className="text-xs text-slate-400 mt-1">{pb.description}</p>
            </div>
          </div>

          {/* Linux Kernel Iptables Command */}
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
                <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                Comando Netfilter / Iptables (Execução no Kali Linux)
              </span>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => handleCopy(pb.iptablesCommand, 'iptables')}
                  className="flex items-center gap-1 text-xs text-cyan-400 hover:text-cyan-300 font-medium"
                >
                  {copiedKey === 'iptables' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copiedKey === 'iptables' ? 'Copiado!' : 'Copiar'}</span>
                </button>
                {onOpenKaliTerminal && (
                  <button
                    onClick={() => onOpenKaliTerminal(pb.iptablesCommand)}
                    className="flex items-center gap-1 px-2.5 py-1 bg-cyan-400 text-slate-950 font-semibold rounded text-[11px] hover:bg-cyan-300 transition-colors shadow-sm"
                    title="Executar imediatamente no terminal do Kali"
                  >
                    <Play className="w-3 h-3 fill-slate-950" />
                    <span>Enviar p/ Terminal</span>
                  </button>
                )}
              </div>
            </div>
            <pre className="p-3 bg-slate-950 rounded-lg border border-slate-800 font-mono text-xs text-emerald-400 overflow-x-auto">
              <code>{pb.iptablesCommand}</code>
            </pre>

            {/* AI Iptables Auditor Widget */}
            <div className="p-3 bg-slate-950/70 rounded-lg border border-slate-800 space-y-2 text-xs">
              <div className="flex items-center justify-between">
                <span className="font-semibold text-slate-300 flex items-center gap-1.5">
                  <Bot className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Auditoria & Sanity-Check da Regra com IA</span>
                </span>
                <button
                  onClick={handleAuditRule}
                  disabled={isAuditing}
                  className="px-2.5 py-1 rounded bg-cyan-950 text-cyan-300 border border-cyan-800/80 hover:bg-cyan-900/60 text-[11px] font-semibold flex items-center gap-1 transition-colors"
                >
                  <Sparkles className={`w-3 h-3 ${isAuditing ? 'animate-spin text-cyan-400' : ''}`} />
                  <span>{isAuditing ? 'Auditando...' : 'Auditar com IA'}</span>
                </button>
              </div>

              {auditResult && (
                <div className="p-2.5 rounded bg-slate-900 border border-slate-800 text-xs space-y-1.5 animate-fadeIn">
                  <div className="flex items-center justify-between">
                    <span className="text-slate-400">Score de Segurança do Firewall:</span>
                    <span className={`font-mono font-bold ${auditResult.safetyScore > 80 ? 'text-emerald-400' : 'text-amber-400'}`}>
                      {auditResult.safetyScore}/100 {auditResult.safetyScore > 80 ? '(Aprovado / Seguro)' : '(Atenção)'}
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-300">
                    {auditResult.improvements}
                  </p>
                  {auditResult.risks.length > 0 && (
                    <ul className="text-[11px] text-slate-400 list-disc list-inside">
                      {auditResult.risks.map((r, i) => (
                        <li key={i}>{r}</li>
                      ))}
                    </ul>
                  )}
                </div>
              )}
            </div>
          </div>

          {/* Forensic / Kali Tool Command */}
          {pb.kaliToolCommand && (
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
                  <Terminal className="w-3.5 h-3.5 text-slate-400" />
                  Comando Forense / Ferramenta Kali
                </span>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => handleCopy(pb.kaliToolCommand, 'kali')}
                    className="flex items-center gap-1 text-xs text-cyan-400 hover:text-cyan-300 font-medium"
                  >
                    {copiedKey === 'kali' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>{copiedKey === 'kali' ? 'Copiado!' : 'Copiar'}</span>
                  </button>
                  {onOpenKaliTerminal && (
                    <button
                      onClick={() => onOpenKaliTerminal(pb.kaliToolCommand)}
                      className="flex items-center gap-1 px-2.5 py-1 bg-slate-800 text-slate-200 font-semibold rounded text-[11px] hover:bg-slate-700 transition-colors"
                      title="Executar imediatamente no terminal do Kali"
                    >
                      <Play className="w-3 h-3" />
                      <span>Enviar p/ Terminal</span>
                    </button>
                  )}
                </div>
              </div>
              <pre className="p-3 bg-slate-950 rounded-lg border border-slate-800 font-mono text-xs text-cyan-300 overflow-x-auto">
                <code>{pb.kaliToolCommand}</code>
              </pre>
            </div>
          )}

          {/* Suricata IDS / IPS Rule if available */}
          {pb.suricataRule && (
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                  Regra Suricata / Snort para Inserção no IDS
                </span>
                <button
                  onClick={() => handleCopy(pb.suricataRule || '', 'suricata')}
                  className="flex items-center gap-1 text-xs text-cyan-400 hover:text-cyan-300 font-medium"
                >
                  {copiedKey === 'suricata' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copiedKey === 'suricata' ? 'Copiado!' : 'Copiar'}</span>
                </button>
              </div>
              <pre className="p-3 bg-slate-950 rounded-lg border border-slate-800 font-mono text-xs text-slate-400 overflow-x-auto">
                <code>{pb.suricataRule}</code>
              </pre>
            </div>
          )}
        </div>

        {/* Footer Actions */}
        <div className="px-6 py-4 border-t border-slate-800 bg-slate-950/80 flex items-center justify-between">
          <div>
            {pb.applied && pb.appliedAt && (
              <span className="text-xs text-slate-400">
                Aplicado às <span className="font-mono text-slate-200">{pb.appliedAt}</span>
              </span>
            )}
          </div>
          <div className="flex items-center gap-3">
            {pb.applied ? (
              <button
                onClick={() => onRollbackMitigation(alert.id)}
                className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium text-amber-400 bg-amber-950/40 border border-amber-800/80 hover:bg-amber-950 transition-colors"
              >
                <RotateCcw className="w-3.5 h-3.5" />
                <span>Desfazer Mitigação (Rollback)</span>
              </button>
            ) : (
              <button
                onClick={() => onApplyMitigation(alert.id)}
                className="flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold text-slate-950 bg-emerald-400 hover:bg-emerald-300 transition-colors shadow-sm"
              >
                <Zap className="w-4 h-4 fill-slate-950" />
                <span>Executar Mitigação Imediata</span>
              </button>
            )}
            <button
              onClick={onClose}
              className="px-4 py-2 rounded-lg text-xs font-medium text-slate-300 bg-slate-800 hover:bg-slate-700 transition-colors"
            >
              Fechar
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
