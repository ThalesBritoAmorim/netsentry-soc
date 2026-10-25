import React, { useState } from 'react';
import { 
  Globe, 
  Shield, 
  AlertTriangle, 
  CheckCircle2, 
  XCircle, 
  Lock, 
  ExternalLink, 
  Terminal, 
  Copy, 
  Check, 
  Search, 
  Sparkles, 
  Filter, 
  Clock, 
  ArrowRight,
  Code2,
  FileText,
  RotateCw,
  Zap
} from 'lucide-react';
import { WebScanResult, WebVulnerability, WebSeverityFilter, SeverityLevel } from '../types';
import { networkEngine } from '../services/networkEngine';

interface WebScannerViewProps {
  onOpenKaliTerminal?: (cmd: string) => void;
  onToast?: (msg: string, type?: 'success' | 'alert') => void;
}

export const WebScannerView: React.FC<WebScannerViewProps> = ({
  onOpenKaliTerminal,
  onToast
}) => {
  const [targetUrl, setTargetUrl] = useState('https://example.com');
  const [severityFilter, setSeverityFilter] = useState<WebSeverityFilter>('all');
  const [scanProfile, setScanProfile] = useState<'quick' | 'full' | 'deep'>('full');
  const [useAI, setUseAI] = useState(true);
  const [isScanning, setIsScanning] = useState(false);
  const [scanResult, setScanResult] = useState<WebScanResult | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [expandedVulnId, setExpandedVulnId] = useState<string | null>(null);
  const [activeCodeTab, setActiveCodeTab] = useState<'nginx' | 'apache' | 'node'>('nginx');
  const [recentScans, setRecentScans] = useState<Array<{ url: string; score: number; date: string; vulnsCount: number }>>([
    { url: 'https://portal.empresa.com.br', score: 65, date: 'Hoje, 02:30', vulnsCount: 4 },
    { url: 'https://api.empresa.com.br', score: 85, date: 'Ontem, 18:15', vulnsCount: 2 },
    { url: 'https://site-institucional.com', score: 45, date: 'Ontem, 14:00', vulnsCount: 7 }
  ]);

  const handleStartScan = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!targetUrl.trim()) {
      if (onToast) onToast('Por favor, informe a URL do site a ser auditado.', 'alert');
      return;
    }

    setIsScanning(true);
    try {
      const result = await networkEngine.runWebScan(targetUrl, severityFilter, scanProfile, useAI);
      setScanResult(result);
      if (onToast) {
        onToast(`Varredura concluída! Score de segurança: ${result.securityScore}/100`, 'success');
      }

      // Add to recent scans
      setRecentScans(prev => [
        {
          url: result.targetUrl,
          score: result.securityScore,
          date: new Date().toLocaleTimeString('pt-BR'),
          vulnsCount: result.vulnerabilities.length
        },
        ...prev.filter(s => s.url !== result.targetUrl).slice(0, 4)
      ]);
    } catch (err: any) {
      if (onToast) {
        onToast(err.message || 'Erro ao realizar a varredura do site.', 'alert');
      }
    } finally {
      setIsScanning(false);
    }
  };

  const handleCopyCode = (id: string, text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
    if (onToast) onToast('Código de mitigação copiado!', 'success');
  };

  const getSeverityBadge = (severity: SeverityLevel) => {
    switch (severity) {
      case 'critical':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-950 text-rose-300 border border-rose-800">
            <XCircle className="w-3 h-3 text-rose-400" />
            CRÍTICO
          </span>
        );
      case 'high':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-950 text-amber-300 border border-amber-800">
            <AlertTriangle className="w-3 h-3 text-amber-400" />
            ALTO
          </span>
        );
      case 'medium':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-yellow-950 text-yellow-300 border border-yellow-800/80">
            MÉDIO
          </span>
        );
      case 'low':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-medium bg-cyan-950 text-cyan-300 border border-cyan-800/60">
            BAIXO
          </span>
        );
      case 'info':
      default:
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono text-slate-300 bg-slate-800 border border-slate-700">
            INFO
          </span>
        );
    }
  };

  const getScoreColor = (score: number) => {
    if (score >= 80) return 'text-emerald-400 stroke-emerald-400';
    if (score >= 55) return 'text-amber-400 stroke-amber-400';
    return 'text-rose-400 stroke-rose-400';
  };

  const getScoreBackground = (score: number) => {
    if (score >= 80) return 'from-emerald-950/40 border-emerald-800/60';
    if (score >= 55) return 'from-amber-950/40 border-amber-800/60';
    return 'from-rose-950/40 border-rose-800/60';
  };

  return (
    <div className="space-y-6">
      {/* 1. Header Title & Mission */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 p-5 rounded-xl bg-slate-900 border border-slate-800 shadow-lg">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <div className="w-8 h-8 rounded-lg bg-cyan-950 border border-cyan-700 flex items-center justify-center text-cyan-400">
              <Globe className="w-4 h-4" />
            </div>
            <h1 className="text-lg font-bold text-slate-100 flex items-center gap-2">
              <span>Auditoria de Vulnerabilidades Web</span>
              <span className="text-[11px] font-mono text-cyan-400 bg-cyan-950 px-2 py-0.5 rounded border border-cyan-800">
                Sites Externos & Públicos
              </span>
            </h1>
          </div>
          <p className="text-xs text-slate-400 max-w-3xl leading-relaxed">
            Avalie a superfície de exposição, integridade SSL/TLS, cabeçalhos HTTP defensivos (HSTS, CSP, X-Frame), vazamento de tecnologias e conformidade OWASP Top 10 com diagnóstico assistido por IA.
          </p>
        </div>

        {/* Quick Tips */}
        <div className="flex items-center gap-2 text-xs font-mono text-slate-400 bg-slate-950 p-2.5 rounded-lg border border-slate-800 self-start lg:self-auto">
          <Shield className="w-4 h-4 text-cyan-400 shrink-0" />
          <span>Filtro de severidade personalizável para relatórios executivos e auditorias.</span>
        </div>
      </div>

      {/* 2. Target URL & Severity Selector Form */}
      <form onSubmit={handleStartScan} className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-4 shadow-md">
        <div className="flex flex-col md:flex-row items-stretch md:items-center gap-3">
          <div className="relative flex-1">
            <Search className="w-4 h-4 absolute left-3.5 top-3 text-slate-500" />
            <input
              type="text"
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              placeholder="Digite a URL do site (ex: https://portal.minhaempresa.com.br ou example.com)..."
              className="w-full pl-10 pr-4 py-2.5 bg-slate-950 border border-slate-700 rounded-lg text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono transition-colors"
              disabled={isScanning}
            />
          </div>

          <button
            type="submit"
            disabled={isScanning}
            className="flex items-center justify-center gap-2 px-6 py-2.5 bg-cyan-400 hover:bg-cyan-300 disabled:opacity-75 text-slate-950 font-bold text-xs rounded-lg transition-all shadow-md shrink-0 cursor-pointer"
          >
            {isScanning ? (
              <>
                <RotateCw className="w-4 h-4 animate-spin" />
                <span>Auditando Site...</span>
              </>
            ) : (
              <>
                <Zap className="w-4 h-4 fill-slate-950" />
                <span>Escanear Vulnerabilidades</span>
              </>
            )}
          </button>
        </div>

        {/* Filter & Scan Level Configuration Row (User explicit requirement) */}
        <div className="pt-3 border-t border-slate-800/80 flex flex-col md:flex-row md:items-center justify-between gap-4 text-xs">
          {/* Severity Level Filter */}
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-slate-400 font-semibold flex items-center gap-1.5">
              <Filter className="w-3.5 h-3.5 text-cyan-400" />
              <span>Nível de Severidade Desejado:</span>
            </span>
            {[
              { id: 'all', label: 'Todas as Severidades' },
              { id: 'critical', label: 'Apenas Críticas' },
              { id: 'high', label: 'Altas & Críticas' },
              { id: 'medium', label: 'Médias ou Superiores' },
              { id: 'low', label: 'Baixas & Informativas' },
              { id: 'info', label: 'Informativas' }
            ].map((f) => (
              <button
                key={f.id}
                type="button"
                onClick={() => setSeverityFilter(f.id as WebSeverityFilter)}
                className={`px-2.5 py-1 rounded-md font-mono text-[11px] transition-colors ${
                  severityFilter === f.id
                    ? 'bg-cyan-950 text-cyan-300 border border-cyan-700 font-bold'
                    : 'text-slate-400 hover:text-slate-200 bg-slate-950 border border-slate-800'
                }`}
              >
                {f.label}
              </button>
            ))}
          </div>

          {/* Scan Profile & AI Toggle */}
          <div className="flex items-center gap-3 shrink-0">
            <div className="flex items-center gap-1.5 bg-slate-950 px-2.5 py-1 rounded-lg border border-slate-800">
              <span className="text-slate-500">Perfil:</span>
              <select
                value={scanProfile}
                onChange={(e) => setScanProfile(e.target.value as any)}
                className="bg-transparent text-slate-300 font-mono text-xs focus:outline-none cursor-pointer"
              >
                <option value="quick" className="bg-slate-900">Rápido (Headers + SSL)</option>
                <option value="full" className="bg-slate-900">Completo (Arquivos + CORS)</option>
                <option value="deep" className="bg-slate-900">Profundo (OWASP + Superfície)</option>
              </select>
            </div>

            <label className="flex items-center gap-1.5 cursor-pointer text-slate-300 select-none">
              <input
                type="checkbox"
                checked={useAI}
                onChange={(e) => setUseAI(e.target.checked)}
                className="rounded border-slate-700 text-cyan-500 focus:ring-0 bg-slate-950"
              />
              <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
              <span>Análise IA</span>
            </label>
          </div>
        </div>
      </form>

      {/* 3. Scan Results Viewport */}
      {scanResult ? (
        <div className="space-y-6 animate-fadeIn">
          {/* Top KPI Cards & Security Score Gauge */}
          <div className="grid grid-cols-1 md:grid-cols-12 gap-4">
            {/* Score Ring Card */}
            <div className={`md:col-span-4 p-5 rounded-xl bg-gradient-to-br to-slate-900 border ${getScoreBackground(scanResult.securityScore)} flex items-center justify-between shadow-lg`}>
              <div className="space-y-1">
                <span className="text-xs uppercase tracking-wider font-semibold text-slate-400">
                  Pontuação de Segurança Web
                </span>
                <div className={`text-4xl font-extrabold font-mono ${getScoreColor(scanResult.securityScore).split(' ')[0]}`}>
                  {scanResult.securityScore}<span className="text-lg text-slate-500">/100</span>
                </div>
                <div className="text-[11px] text-slate-400 mt-1">
                  {scanResult.securityScore >= 80 ? 'Postura Defensiva Robusta' : scanResult.securityScore >= 55 ? 'Postura Moderada com Falhas' : 'Postura Crítica - Requer Ação Imediata'}
                </div>
              </div>

              {/* Gauge SVG */}
              <div className="relative w-20 h-20 flex items-center justify-center shrink-0">
                <svg className="w-full h-full transform -rotate-90" viewBox="0 0 36 36">
                  <path
                    className="text-slate-800"
                    strokeWidth="3.5"
                    stroke="currentColor"
                    fill="none"
                    d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                  />
                  <path
                    className={getScoreColor(scanResult.securityScore).split(' ')[1]}
                    strokeDasharray={`${scanResult.securityScore}, 100`}
                    strokeWidth="3.5"
                    strokeLinecap="round"
                    stroke="currentColor"
                    fill="none"
                    d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                  />
                </svg>
                <Shield className={`w-6 h-6 absolute ${getScoreColor(scanResult.securityScore).split(' ')[0]}`} />
              </div>
            </div>

            {/* Telemetry KPI Cards */}
            <div className="md:col-span-8 grid grid-cols-2 sm:grid-cols-4 gap-3">
              <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
                <span className="text-[11px] text-slate-500 block uppercase font-medium">Vulnerabilidades</span>
                <span className="text-2xl font-bold font-mono text-slate-100">{scanResult.vulnerabilities.length}</span>
                <span className="text-[10px] text-slate-400 block mt-1">
                  Filtrado: <strong className="text-cyan-300">{severityFilter.toUpperCase()}</strong>
                </span>
              </div>

              <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
                <span className="text-[11px] text-slate-500 block uppercase font-medium">Status SSL/TLS</span>
                <span className={`text-base font-bold font-mono flex items-center gap-1.5 ${scanResult.sslStatus.valid ? 'text-emerald-400' : 'text-rose-400'}`}>
                  <Lock className="w-4 h-4" />
                  {scanResult.sslStatus.valid ? 'Válido' : 'Inválido'}
                </span>
                <span className="text-[10px] text-slate-400 block mt-1 truncate" title={scanResult.sslStatus.issuer || 'Sem TLS'}>
                  {scanResult.sslStatus.daysRemaining ? `${scanResult.sslStatus.daysRemaining} dias restantes` : scanResult.sslStatus.error || 'N/A'}
                </span>
              </div>

              <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
                <span className="text-[11px] text-slate-500 block uppercase font-medium">Headers Faltantes</span>
                <span className="text-2xl font-bold font-mono text-amber-400">{scanResult.missingHeaders.length}</span>
                <span className="text-[10px] text-slate-400 block mt-1">HSTS, CSP, X-Frame</span>
              </div>

              <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
                <span className="text-[11px] text-slate-500 block uppercase font-medium">Duração do Scan</span>
                <span className="text-2xl font-bold font-mono text-slate-200">{(scanResult.scanDurationMs / 1000).toFixed(1)}s</span>
                <span className="text-[10px] text-emerald-400 block mt-1">Auditado às {scanResult.timestamp}</span>
              </div>
            </div>
          </div>

          {/* AI Executive Forensic Analysis Card */}
          {scanResult.aiExecutiveSummary && (
            <div className="p-5 rounded-xl bg-gradient-to-r from-slate-900 via-indigo-950/40 to-slate-900 border border-indigo-800/60 shadow-lg space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <div className="p-1.5 rounded-md bg-indigo-950 border border-indigo-700 text-cyan-400">
                    <Sparkles className="w-4 h-4" />
                  </div>
                  <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                    <span>Diagnóstico Executivo de Cibersegurança Web (IA Gemini)</span>
                    <span className="text-[10px] font-mono bg-indigo-950 text-indigo-300 px-2 py-0.5 rounded border border-indigo-800">
                      Análise de Riscos
                    </span>
                  </h3>
                </div>
              </div>

              <p className="text-xs text-slate-300 leading-relaxed font-sans whitespace-pre-line">
                {scanResult.aiExecutiveSummary}
              </p>

              {scanResult.aiRemediationRoadmap && scanResult.aiRemediationRoadmap.length > 0 && (
                <div className="pt-3 border-t border-indigo-900/40">
                  <span className="text-[11px] font-semibold uppercase tracking-wider text-indigo-300 block mb-2">
                    Roadmap Priorizado de Correção
                  </span>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs">
                    {scanResult.aiRemediationRoadmap.map((step, idx) => (
                      <div key={idx} className="flex items-start gap-2 p-2 rounded-lg bg-slate-950/60 border border-slate-800/80">
                        <span className="text-cyan-400 font-mono font-bold shrink-0">{idx + 1}.</span>
                        <span className="text-slate-300 font-sans">{step}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* 4. Vulnerabilities Discovered List */}
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <h2 className="text-base font-semibold text-slate-100 flex items-center gap-2">
                <span>Vulnerabilidades & Pontos de Atenção</span>
                <span className="text-xs font-mono text-cyan-400 bg-cyan-950 px-2 py-0.5 rounded border border-cyan-800">
                  {scanResult.vulnerabilities.length} encontradas
                </span>
              </h2>

              <div className="flex items-center gap-2">
                {onOpenKaliTerminal && (
                  <button
                    onClick={() => onOpenKaliTerminal(`curl -I -s -L ${scanResult.targetUrl} | grep -iE 'server|strict|content-security|x-frame|set-cookie'`)}
                    className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-700 rounded-lg text-xs font-mono transition-colors"
                    title="Inspecionar cabeçalhos diretamente no terminal do Kali"
                  >
                    <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                    <span>Inspecionar no Kali</span>
                  </button>
                )}
              </div>
            </div>

            {scanResult.vulnerabilities.length === 0 ? (
              <div className="p-8 text-center rounded-xl bg-slate-900 border border-slate-800 space-y-2">
                <CheckCircle2 className="w-8 h-8 text-emerald-400 mx-auto" />
                <div className="text-sm font-semibold text-slate-200">
                  Nenhuma vulnerabilidade encontrada para o filtro "{severityFilter.toUpperCase()}"!
                </div>
                <p className="text-xs text-slate-400 max-w-md mx-auto">
                  O site atende aos requisitos definidos para este nível de severidade. Experimente selecionar "Todas as Severidades" para inspecionar recomendações de boas práticas.
                </p>
              </div>
            ) : (
              <div className="space-y-3">
                {scanResult.vulnerabilities.map((vuln) => {
                  const isExpanded = expandedVulnId === vuln.id;
                  return (
                    <div
                      key={vuln.id}
                      className="rounded-xl bg-slate-900 border border-slate-800 hover:border-slate-700 transition-all overflow-hidden"
                    >
                      <div
                        className="p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3 cursor-pointer"
                        onClick={() => setExpandedVulnId(isExpanded ? null : vuln.id)}
                      >
                        <div className="space-y-1.5">
                          <div className="flex items-center gap-2 flex-wrap">
                            {getSeverityBadge(vuln.severity)}
                            <h4 className="text-sm font-semibold text-slate-100 hover:text-cyan-300 transition-colors">
                              {vuln.title}
                            </h4>
                            {vuln.cwe && (
                              <span className="text-[10px] font-mono text-slate-500 bg-slate-950 px-1.5 py-0.5 rounded border border-slate-800">
                                {vuln.cwe}
                              </span>
                            )}
                          </div>
                          <p className="text-xs text-slate-400 leading-relaxed font-sans line-clamp-2">
                            {vuln.description}
                          </p>
                        </div>

                        <div className="flex items-center gap-2 shrink-0">
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              setExpandedVulnId(isExpanded ? null : vuln.id);
                            }}
                            className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 transition-colors flex items-center gap-1.5"
                          >
                            <Code2 className="w-3.5 h-3.5 text-cyan-400" />
                            <span>{isExpanded ? 'Recolher' : 'Ver Correção'}</span>
                          </button>
                        </div>
                      </div>

                      {/* Expanded Details & Remediation Code */}
                      {isExpanded && (
                        <div className="p-4 bg-slate-950 border-t border-slate-800/80 space-y-3 text-xs">
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                            <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 space-y-1">
                              <span className="text-[11px] font-bold text-amber-400 uppercase tracking-wider block">
                                Impacto da Falha
                              </span>
                              <p className="text-slate-300 leading-relaxed">
                                {vuln.impact}
                              </p>
                            </div>

                            <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 space-y-1">
                              <span className="text-[11px] font-bold text-cyan-400 uppercase tracking-wider block">
                                Recomendação Técnica
                              </span>
                              <p className="text-slate-300 leading-relaxed">
                                {vuln.remediation}
                              </p>
                            </div>
                          </div>

                          {/* Remediation Code Snippet */}
                          {vuln.codeSnippet && (
                            <div className="space-y-2">
                              <div className="flex items-center justify-between">
                                <span className="text-[11px] font-semibold text-slate-400 flex items-center gap-1.5 font-mono">
                                  <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                                  <span>Snippet de Configuração Pronto para Aplicar</span>
                                </span>

                                <button
                                  onClick={() => handleCopyCode(vuln.id, vuln.codeSnippet || '')}
                                  className="flex items-center gap-1 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[11px] font-mono transition-colors"
                                >
                                  {copiedId === vuln.id ? (
                                    <>
                                      <Check className="w-3 h-3 text-emerald-400" />
                                      <span className="text-emerald-400">Copiado</span>
                                    </>
                                  ) : (
                                    <>
                                      <Copy className="w-3 h-3 text-slate-400" />
                                      <span>Copiar Código</span>
                                    </>
                                  )}
                                </button>
                              </div>

                              <pre className="p-3 rounded-lg bg-black border border-slate-800 text-emerald-400 font-mono text-[11px] overflow-x-auto whitespace-pre-wrap leading-relaxed">
                                {vuln.codeSnippet}
                              </pre>
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>
      ) : (
        /* Empty State & Recent Scans History */
        <div className="grid grid-cols-1 md:grid-cols-12 gap-6">
          <div className="md:col-span-8 p-8 rounded-xl bg-slate-900 border border-slate-800 text-center space-y-4">
            <div className="w-16 h-16 rounded-2xl bg-cyan-950/60 border border-cyan-800 flex items-center justify-center mx-auto text-cyan-400 shadow-inner">
              <Globe className="w-8 h-8" />
            </div>
            <div className="space-y-1.5">
              <h3 className="text-base font-bold text-slate-100">
                Pronto para auditar a segurança web da sua organização
              </h3>
              <p className="text-xs text-slate-400 max-w-md mx-auto leading-relaxed">
                Digite a URL do site corporativo no campo acima e selecione o nível de severidade desejado para iniciar a análise completa.
              </p>
            </div>

            <div className="pt-2 flex items-center justify-center gap-2 flex-wrap">
              <span className="text-xs text-slate-500">Exemplos rápidos:</span>
              {['https://google.com', 'https://cloudflare.com', 'https://example.com'].map((u) => (
                <button
                  key={u}
                  onClick={() => {
                    setTargetUrl(u);
                  }}
                  className="px-2.5 py-1 rounded bg-slate-950 border border-slate-800 hover:border-cyan-600 text-[11px] font-mono text-slate-300 transition-colors"
                >
                  {u}
                </button>
              ))}
            </div>
          </div>

          {/* Recent Scans History */}
          <div className="md:col-span-4 p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-200 flex items-center gap-1.5">
                <Clock className="w-3.5 h-3.5 text-cyan-400" />
                <span>Auditorias Recentes</span>
              </h3>
              <span className="text-[10px] text-slate-500 font-mono">Histórico</span>
            </div>

            <div className="space-y-2">
              {recentScans.map((scan, idx) => (
                <div
                  key={idx}
                  onClick={() => {
                    setTargetUrl(scan.url);
                    handleStartScan();
                  }}
                  className="p-3 rounded-lg bg-slate-950 border border-slate-800 hover:border-cyan-700 transition-all cursor-pointer group"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-xs font-semibold text-slate-200 group-hover:text-cyan-300 truncate max-w-[180px]">
                      {scan.url.replace(/^https?:\/\//, '')}
                    </span>
                    <span className={`text-xs font-mono font-bold ${getScoreColor(scan.score).split(' ')[0]}`}>
                      {scan.score}/100
                    </span>
                  </div>
                  <div className="flex items-center justify-between text-[11px] text-slate-500 mt-1">
                    <span>{scan.date}</span>
                    <span>{scan.vulnsCount} apontamentos</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
