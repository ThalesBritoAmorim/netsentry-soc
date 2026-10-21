import React, { useState } from 'react';
import { 
  SecurityReport, 
  DatabaseBackup, 
  UserAccount, 
  AuditLogEntry, 
  ThreatAlert, 
  NetworkDevice 
} from '../types';
import { INITIAL_USERS } from '../services/initialData';
import { generateConsolidatedPDFReport } from '../services/pdfReportGenerator';
import { 
  FileText, 
  Database, 
  ShieldCheck, 
  Download, 
  Printer, 
  Clock, 
  RotateCw, 
  CheckCircle2, 
  Users, 
  Shield, 
  AlertTriangle,
  Lock,
  ExternalLink,
  FileDown,
  Check,
  ShieldAlert
} from 'lucide-react';

interface ReportsBackupViewProps {
  alerts: ThreatAlert[];
  devices: NetworkDevice[];
  backups: DatabaseBackup[];
  auditLogs: AuditLogEntry[];
  onTriggerBackup: () => void;
}

export const ReportsBackupView: React.FC<ReportsBackupViewProps> = ({
  alerts,
  devices,
  backups,
  auditLogs,
  onTriggerBackup
}) => {
  const [activeSection, setActiveSection] = useState<'reports' | 'backup' | 'rbac'>('reports');
  const [reportGenerated, setReportGenerated] = useState<SecurityReport | null>(null);
  const [isGeneratingPdf, setIsGeneratingPdf] = useState(false);
  const [pdfDownloaded, setPdfDownloaded] = useState(false);

  const handleExportPDF = () => {
    setIsGeneratingPdf(true);
    if (!reportGenerated) {
      handleGenerateReport();
    }
    setTimeout(() => {
      try {
        generateConsolidatedPDFReport({
          alerts,
          devices,
          auditLogs,
          author: 'Thales Brito Amorim (SecOps Admin)',
          period: 'Últimas 24 Horas'
        });
        setPdfDownloaded(true);
        setTimeout(() => setPdfDownloaded(false), 3500);
      } catch (err) {
        console.error('Erro ao gerar relatório em PDF:', err);
      } finally {
        setIsGeneratingPdf(false);
      }
    }, 350);
  };

  // Generate real dynamic report based on current alerts and devices
  const handleGenerateReport = () => {
    const totalAlerts = alerts.length;
    const criticalAlerts = alerts.filter(a => a.severity === 'critical').length;
    const mitigatedAlerts = alerts.filter(a => a.playbook.applied).length;
    const avgScore = devices.length > 0 
      ? Math.round(devices.reduce((acc, d) => acc + d.threatScore, 0) / devices.length) 
      : 0;

    const actionPlan: string[] = [];
    alerts.forEach(a => {
      if (!a.playbook.applied) {
        actionPlan.push(`Aplicar mitigação recomendada para ${a.title} (${a.sourceIp}): ${a.playbook.actionName}.`);
      } else {
        actionPlan.push(`Manter regra de firewall ativa para ${a.sourceIp} (${a.playbook.actionName}).`);
      }
    });
    devices.filter(d => d.openPorts.some(p => p.risk === 'critical' || p.risk === 'high')).forEach(d => {
      const riskyPorts = d.openPorts.filter(p => p.risk === 'critical' || p.risk === 'high').map(p => `${p.port}/${p.service}`).join(', ');
      actionPlan.push(`Revisar e restringir portas de alto risco no host ${d.hostname} (${d.ip}): ${riskyPorts}.`);
    });

    if (actionPlan.length === 0) {
      actionPlan.push('Manter o sensor de tráfego Scapy ativo em modo promíscuo no Kali Linux.');
      actionPlan.push('Executar varredura de sub-rede periódica (ARP/Nmap) para catalogação contínua de novos ativos.');
      actionPlan.push('Garantir que as regras de mitigação autônoma permaneçam habilitadas no kernel Netfilter.');
    }

    const report: SecurityReport = {
      id: `rep-${Date.now()}`,
      title: 'Relatório Executivo de Segurança & Gestão de Vulnerabilidades de Rede',
      generatedAt: new Date().toLocaleString('pt-BR'),
      author: 'Thales Brito Amorim (SecOps Admin)',
      period: 'Últimas 24 Horas',
      summary: `Durante o período de monitoramento, foram inspecionados ${devices.length} dispositivos reais na rede local. O sistema autônomo NetSentry identificou ${totalAlerts} incidentes anômalos, dos quais ${mitigatedAlerts} foram mitigados com regras de netfilter do kernel Linux. A postura média de risco da infraestrutura encontra-se em ${avgScore}/100.`,
      totalAlerts,
      criticalAlerts,
      mitigatedAlerts,
      devicesScanned: devices.length,
      threatScoreAverage: avgScore,
      executiveActionPlan: actionPlan
    };
    setReportGenerated(report);
  };

  const handlePrint = () => {
    window.print();
  };

  const handleDownloadMarkdown = () => {
    if (!reportGenerated) return;
    const md = `# ${reportGenerated.title}
**Data:** ${reportGenerated.generatedAt}
**Auditor Responsável:** ${reportGenerated.author}
**Período:** ${reportGenerated.period}

## 1. Sumário Executivo
${reportGenerated.summary}

## 2. Indicadores Principais de Segurança
- Dispositivos Escaneados: ${reportGenerated.devicesScanned}
- Ameaças Detectadas: ${reportGenerated.totalAlerts}
- Incidentes Críticos: ${reportGenerated.criticalAlerts}
- Mitigações Aplicadas: ${reportGenerated.mitigatedAlerts}
- Média de Risco de Rede: ${reportGenerated.threatScoreAverage}/100

## 3. Plano de Ação Recomendado (Mitigações)
${reportGenerated.executiveActionPlan.map((item, idx) => `${idx + 1}. ${item}`).join('\n')}

---
*Gerado automaticamente pelo NetSentry Kali SOC v2.4*
`;
    const blob = new Blob([md], { type: 'text/markdown;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', `relatorio_seguranca_${Date.now()}.md`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  return (
    <div className="space-y-6">
      {/* 1. Header & Segmented Tabs */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-base font-semibold text-slate-100 flex items-center gap-2">
            <span>Gestão de Conformidade, Backups & Controle de Acesso</span>
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Relatórios de vulnerabilidades, snapshots do PostgreSQL e trilha de auditoria para compliance.
          </p>
        </div>

        {/* Tab Controls */}
        <div className="flex items-center gap-1 p-1 bg-slate-900 rounded-lg border border-slate-800 self-start sm:self-auto text-xs">
          <button
            onClick={() => setActiveSection('reports')}
            className={`px-3 py-1.5 rounded-md font-medium transition-colors ${
              activeSection === 'reports' ? 'bg-slate-800 text-cyan-300' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Relatórios Executivos
          </button>
          <button
            onClick={() => setActiveSection('backup')}
            className={`px-3 py-1.5 rounded-md font-medium transition-colors ${
              activeSection === 'backup' ? 'bg-slate-800 text-cyan-300' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Backup PostgreSQL
          </button>
          <button
            onClick={() => setActiveSection('rbac')}
            className={`px-3 py-1.5 rounded-md font-medium transition-colors ${
              activeSection === 'rbac' ? 'bg-slate-800 text-cyan-300' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Controle de Acesso & Auditoria
          </button>
        </div>
      </div>

      {/* SECTION 1: RELATÓRIOS EXECUTIVOS */}
      {activeSection === 'reports' && (
        <div className="space-y-4">
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div>
              <h3 className="text-sm font-semibold text-slate-200">
                Gerador de Relatório de Vulnerabilidades, Dispositivos & Auditoria
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Consolida histórico de ataques detectados, dispositivos confiáveis cadastrados e a trilha de auditoria para conformidade.
              </p>
            </div>

            <div className="flex items-center gap-2 flex-wrap">
              <button
                onClick={handleExportPDF}
                disabled={isGeneratingPdf}
                className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg text-xs font-semibold text-white bg-rose-600 hover:bg-rose-500 transition-all shadow-md active:scale-95 disabled:opacity-50"
              >
                {pdfDownloaded ? (
                  <>
                    <Check className="w-3.5 h-3.5 text-white" />
                    <span>PDF Baixado!</span>
                  </>
                ) : isGeneratingPdf ? (
                  <>
                    <RotateCw className="w-3.5 h-3.5 animate-spin text-white" />
                    <span>Gerando PDF...</span>
                  </>
                ) : (
                  <>
                    <FileDown className="w-3.5 h-3.5" />
                    <span>Exportar PDF Consolidado</span>
                  </>
                )}
              </button>

              <button
                onClick={handleGenerateReport}
                className="px-3.5 py-1.5 rounded-lg text-xs font-semibold text-slate-950 bg-cyan-400 hover:bg-cyan-300 transition-colors shadow-sm"
              >
                {reportGenerated ? 'Atualizar Dados' : 'Compilar no Painel'}
              </button>
            </div>
          </div>

          {reportGenerated ? (
            <div className="p-6 rounded-xl bg-slate-900 border border-slate-800 space-y-6 text-slate-200 shadow-xl">
              {/* Report Header Actions */}
              <div className="flex flex-col sm:flex-row sm:items-center justify-between border-b border-slate-800 pb-4 gap-3">
                <div>
                  <h3 className="text-base font-bold text-slate-100">{reportGenerated.title}</h3>
                  <div className="flex items-center gap-2 text-xs text-slate-400 mt-1 flex-wrap">
                    <span>Emissão: <strong className="text-slate-300">{reportGenerated.generatedAt}</strong></span>
                    <span aria-hidden="true">·</span>
                    <span>Auditor: <strong className="text-slate-300">{reportGenerated.author}</strong></span>
                    <span aria-hidden="true">·</span>
                    <span className="font-mono text-cyan-400">PDF Consolidado A4 Pronto</span>
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    onClick={handleExportPDF}
                    disabled={isGeneratingPdf}
                    className="flex items-center gap-1 px-3 py-1.5 rounded-md text-xs font-semibold text-white bg-rose-600 hover:bg-rose-500 transition-colors shadow-sm"
                  >
                    <FileDown className="w-3.5 h-3.5" />
                    <span>Baixar PDF</span>
                  </button>
                  <button
                    onClick={handleDownloadMarkdown}
                    className="flex items-center gap-1 px-3 py-1.5 rounded-md text-xs font-medium text-slate-300 bg-slate-800 hover:bg-slate-700 transition-colors"
                  >
                    <Download className="w-3.5 h-3.5 text-cyan-400" />
                    <span>Markdown</span>
                  </button>
                  <button
                    onClick={handlePrint}
                    className="flex items-center gap-1 px-3 py-1.5 rounded-md text-xs font-medium text-slate-300 bg-slate-800 hover:bg-slate-700 transition-colors"
                  >
                    <Printer className="w-3.5 h-3.5" />
                    <span>Imprimir</span>
                  </button>
                </div>
              </div>

              {/* Executive Summary */}
              <div className="space-y-2">
                <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                  Sumário Executivo & Postura de Rede
                </h4>
                <p className="text-xs text-slate-300 leading-relaxed bg-slate-950/60 p-3.5 rounded-lg border border-slate-800">
                  {reportGenerated.summary}
                </p>
              </div>

              {/* KPI Grid */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                  <span className="text-slate-500 block">Dispositivos Escaneados</span>
                  <span className="text-lg font-bold font-mono text-slate-100">{reportGenerated.devicesScanned}</span>
                </div>
                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                  <span className="text-slate-500 block">Ameaças Detectadas</span>
                  <span className="text-lg font-bold font-mono text-rose-400">{reportGenerated.totalAlerts}</span>
                </div>
                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                  <span className="text-slate-500 block">Mitigações Concluídas</span>
                  <span className="text-lg font-bold font-mono text-emerald-400">{reportGenerated.mitigatedAlerts}</span>
                </div>
                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                  <span className="text-slate-500 block">Média de Risco Global</span>
                  <span className="text-lg font-bold font-mono text-amber-400">{reportGenerated.threatScoreAverage}/100</span>
                </div>
              </div>

              {/* CONSOLIDATED SECTION 1: Resumo dos Incidentes Detectados */}
              <div className="space-y-2.5">
                <div className="flex items-center justify-between">
                  <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
                    <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
                    <span>1. Resumo dos Incidentes & Ameaças Detectadas ({alerts.length})</span>
                  </h4>
                  <span className="text-[11px] text-slate-500 font-mono">
                    {alerts.filter(a => a.playbook?.applied).length} mitigados
                  </span>
                </div>

                <div className="rounded-lg border border-slate-800 overflow-hidden text-xs">
                  <div className="overflow-x-auto max-h-56">
                    <table className="w-full text-left">
                      <thead className="bg-slate-950 text-slate-400 text-[11px] border-b border-slate-800 sticky top-0">
                        <tr>
                          <th className="py-2 px-3">Horário</th>
                          <th className="py-2 px-3">Incidente / Ameaça</th>
                          <th className="py-2 px-3">Severidade</th>
                          <th className="py-2 px-3">Origem</th>
                          <th className="py-2 px-3">Alvo</th>
                          <th className="py-2 px-3">Status Netfilter</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/60 bg-slate-950/40 text-slate-300 font-mono text-[11px]">
                        {alerts.length === 0 ? (
                          <tr><td colSpan={6} className="py-3 px-3 text-center text-slate-500">Nenhum incidente registrado.</td></tr>
                        ) : alerts.map((a) => (
                          <tr key={a.id} className="hover:bg-slate-800/30">
                            <td className="py-2 px-3 text-slate-400 whitespace-nowrap">{a.timestamp?.slice(11, 19) || a.timestamp}</td>
                            <td className="py-2 px-3 font-sans font-medium text-slate-200">{a.title}</td>
                            <td className="py-2 px-3">
                              <span className={`px-1.5 py-0.2 rounded font-bold uppercase text-[10px] ${
                                a.severity === 'critical' ? 'bg-rose-950 text-rose-300' :
                                a.severity === 'high' ? 'bg-amber-950 text-amber-300' : 'bg-cyan-950 text-cyan-300'
                              }`}>
                                {a.severity}
                              </span>
                            </td>
                            <td className="py-2 px-3 text-cyan-300">{a.sourceIp}</td>
                            <td className="py-2 px-3 text-slate-400">{a.targetIp}</td>
                            <td className="py-2 px-3 font-sans">
                              {a.playbook?.applied ? (
                                <span className="text-emerald-400 font-semibold flex items-center gap-1">
                                  <CheckCircle2 className="w-3 h-3" />
                                  <span>Mitigado</span>
                                </span>
                              ) : (
                                <span className="text-rose-400 font-semibold">Ativo</span>
                              )}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              </div>

              {/* CONSOLIDATED SECTION 2: Dispositivos Confiáveis & Inventário */}
              <div className="space-y-2.5">
                <div className="flex items-center justify-between">
                  <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
                    <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
                    <span>2. Inventário de Dispositivos Confiáveis & Postura ({devices.length} hosts)</span>
                  </h4>
                  <span className="text-[11px] text-emerald-400 font-mono">
                    {devices.filter(d => d.trustLevel === 'trusted').length} nós confiáveis
                  </span>
                </div>

                <div className="rounded-lg border border-slate-800 overflow-hidden text-xs">
                  <div className="overflow-x-auto max-h-56">
                    <table className="w-full text-left">
                      <thead className="bg-slate-950 text-slate-400 text-[11px] border-b border-slate-800 sticky top-0">
                        <tr>
                          <th className="py-2 px-3">Endereço IP</th>
                          <th className="py-2 px-3">MAC</th>
                          <th className="py-2 px-3">Hostname</th>
                          <th className="py-2 px-3">Fabricante</th>
                          <th className="py-2 px-3">Confiabilidade</th>
                          <th className="py-2 px-3">Score Risco</th>
                          <th className="py-2 px-3">Status</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/60 bg-slate-950/40 text-slate-300 font-mono text-[11px]">
                        {devices.map((d) => (
                          <tr key={d.id} className="hover:bg-slate-800/30">
                            <td className="py-2 px-3 font-bold text-cyan-300">{d.ip}</td>
                            <td className="py-2 px-3 text-slate-400">{d.mac}</td>
                            <td className="py-2 px-3 font-sans text-slate-200">{d.hostname}</td>
                            <td className="py-2 px-3 font-sans text-slate-400 truncate max-w-xs">{d.vendor}</td>
                            <td className="py-2 px-3 font-sans">
                              <span className={`px-1.5 py-0.2 rounded font-bold uppercase text-[10px] ${
                                d.trustLevel === 'trusted' ? 'bg-emerald-950 text-emerald-300 border border-emerald-800' :
                                d.trustLevel === 'quarantined' ? 'bg-rose-950 text-rose-300 border border-rose-800' :
                                'bg-slate-800 text-slate-300'
                              }`}>
                                {d.trustLevel === 'trusted' ? 'Confiável' : d.trustLevel}
                              </span>
                            </td>
                            <td className="py-2 px-3 font-bold text-slate-200">{d.threatScore}/100</td>
                            <td className="py-2 px-3 font-sans">
                              <span className={d.isOnline ? 'text-emerald-400' : 'text-slate-500'}>
                                {d.isOnline ? 'Online' : 'Offline'}
                              </span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              </div>

              {/* CONSOLIDATED SECTION 3: Logs de Auditoria Recentes */}
              <div className="space-y-2.5">
                <div className="flex items-center justify-between">
                  <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
                    <Clock className="w-3.5 h-3.5 text-indigo-400" />
                    <span>3. Trilha de Auditoria Recente & Compliance ({auditLogs.length} eventos)</span>
                  </h4>
                  <span className="text-[11px] text-slate-500 font-mono">
                    Registros imutáveis
                  </span>
                </div>

                <div className="rounded-lg border border-slate-800 overflow-hidden text-xs">
                  <div className="overflow-x-auto max-h-56">
                    <table className="w-full text-left">
                      <thead className="bg-slate-950 text-slate-400 text-[11px] border-b border-slate-800 sticky top-0">
                        <tr>
                          <th className="py-2 px-3">Horário</th>
                          <th className="py-2 px-3">Operador / Agente</th>
                          <th className="py-2 px-3">Ação Executada</th>
                          <th className="py-2 px-3">Alvo</th>
                          <th className="py-2 px-3">Resultado</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/60 bg-slate-950/40 text-slate-300 font-mono text-[11px]">
                        {auditLogs.slice(0, 8).map((l) => (
                          <tr key={l.id} className="hover:bg-slate-800/30">
                            <td className="py-2 px-3 text-slate-400 whitespace-nowrap">{l.timestamp}</td>
                            <td className="py-2 px-3 text-cyan-300 font-semibold">{l.operator}</td>
                            <td className="py-2 px-3 font-sans text-slate-200">{l.action}</td>
                            <td className="py-2 px-3 text-slate-400 truncate max-w-xs">{l.target}</td>
                            <td className="py-2 px-3 font-sans">
                              <span className={`px-1.5 py-0.2 rounded font-bold uppercase text-[10px] ${
                                l.status === 'success' ? 'bg-emerald-950 text-emerald-300' : 'bg-amber-950 text-amber-300'
                              }`}>
                                {l.status}
                              </span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              </div>

              {/* Action Plan */}
              <div className="space-y-2">
                <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                  4. Plano de Ação Recomendado (Hardening & Mitigações)
                </h4>
                <div className="space-y-2">
                  {reportGenerated.executiveActionPlan.map((action, idx) => (
                    <div
                      key={idx}
                      className="p-3 rounded-lg bg-slate-950 border border-slate-800 flex items-start gap-2.5 text-xs"
                    >
                      <span className="font-mono text-cyan-400 font-bold">{idx + 1}.</span>
                      <p className="text-slate-300 leading-relaxed">{action}</p>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          ) : (
            <div className="p-12 text-center bg-slate-900/40 rounded-xl border border-slate-800 space-y-3">
              <FileText className="w-10 h-10 text-slate-600 mx-auto" />
              <p className="text-sm font-medium text-slate-300">
                Nenhum relatório compilado na sessão atual
              </p>
              <p className="text-xs text-slate-500 max-w-md mx-auto">
                Clique abaixo para gerar o relatório consolidado em PDF contendo o resumo dos incidentes detectados, inventário de dispositivos confiáveis e logs de auditoria.
              </p>
              <div className="flex items-center justify-center gap-3">
                <button
                  onClick={handleExportPDF}
                  disabled={isGeneratingPdf}
                  className="flex items-center gap-1.5 px-4 py-2 rounded-lg text-xs font-semibold text-white bg-rose-600 hover:bg-rose-500 transition-all shadow-md active:scale-95 disabled:opacity-50"
                >
                  <FileDown className="w-4 h-4" />
                  <span>Gerar e Baixar Relatório em PDF Consolidado</span>
                </button>
                <button
                  onClick={handleGenerateReport}
                  className="px-4 py-2 rounded-lg text-xs font-semibold text-slate-950 bg-cyan-400 hover:bg-cyan-300 transition-colors shadow-sm"
                >
                  Visualizar no Painel
                </button>
              </div>
            </div>
          )}
        </div>
      )}

      {/* SECTION 2: BACKUPS POSTGRESQL */}
      {activeSection === 'backup' && (
        <div className="space-y-4">
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div>
              <h3 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                <Database className="w-4 h-4 text-cyan-400" />
                <span>Gerenciador de Backups & Snapshots PostgreSQL 16</span>
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Backups automatizados e manuais via <code className="text-cyan-400 font-mono">pg_dump</code> com verificação de integridade de hash.
              </p>
            </div>

            <button
              onClick={onTriggerBackup}
              className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg text-xs font-semibold text-slate-950 bg-cyan-400 hover:bg-cyan-300 transition-colors shadow-sm self-start sm:self-auto"
            >
              <RotateCw className="w-3.5 h-3.5" />
              <span>Criar Snapshot Manual Agora</span>
            </button>
          </div>

          {/* Backup Snapshots Table */}
          <div className="rounded-xl border border-slate-800 bg-slate-900 overflow-hidden font-mono text-xs">
            <table className="w-full text-left">
              <thead className="bg-slate-950 text-slate-400 border-b border-slate-800 uppercase text-[11px]">
                <tr>
                  <th className="py-3 px-4">Arquivo de Backup</th>
                  <th className="py-3 px-4">Tamanho</th>
                  <th className="py-3 px-4">Registros Catalogados</th>
                  <th className="py-3 px-4">Data / Hora</th>
                  <th className="py-3 px-4">Tipo</th>
                  <th className="py-3 px-4 text-center">Status</th>
                  <th className="py-3 px-4 text-right">Ações</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-slate-300">
                {backups.map((bk) => (
                  <tr key={bk.id} className="hover:bg-slate-800/40 transition-colors">
                    <td className="py-3 px-4 font-semibold text-cyan-300">
                      {bk.filename}
                    </td>
                    <td className="py-3 px-4 tabular-nums">
                      {bk.sizeMb} MB
                    </td>
                    <td className="py-3 px-4 tabular-nums">
                      {bk.tableRowsCount.toLocaleString('pt-BR')} linhas
                    </td>
                    <td className="py-3 px-4 text-slate-400">
                      {bk.createdAt}
                    </td>
                    <td className="py-3 px-4 font-sans capitalize">
                      {bk.type === 'scheduled' ? 'Automático (Cron)' : 'Manual (Admin)'}
                    </td>
                    <td className="py-3 px-4 text-center font-sans">
                      <span className="inline-flex items-center gap-1 text-[11px] text-emerald-400 font-medium bg-emerald-950/60 px-2 py-0.5 rounded border border-emerald-800">
                        <CheckCircle2 className="w-3 h-3" />
                        <span>Verificado</span>
                      </span>
                    </td>
                    <td className="py-3 px-4 text-right font-sans">
                      <button
                        onClick={() => alert(`Download simulado de ${bk.filename}`)}
                        className="p-1 text-slate-400 hover:text-cyan-400 rounded hover:bg-slate-800 transition-colors"
                        title="Baixar arquivo de dump"
                      >
                        <Download className="w-4 h-4" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* SECTION 3: RBAC & AUDITORIA */}
      {activeSection === 'rbac' && (
        <div className="space-y-4">
          {/* User Accounts Matrix */}
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
            <h3 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
              <Users className="w-4 h-4 text-cyan-400" />
              <span>Controle de Acesso Baseado em Papéis (RBAC)</span>
            </h3>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              {INITIAL_USERS.map((user) => (
                <div
                  key={user.id}
                  className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 space-y-2 text-xs"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-slate-100">{user.name}</span>
                    <span className={`text-[10px] uppercase font-bold px-1.5 py-0.5 rounded ${
                      user.role === 'admin' ? 'bg-cyan-950 text-cyan-300 border border-cyan-800' :
                      user.role === 'analyst' ? 'bg-indigo-950 text-indigo-300 border border-indigo-800' :
                      'bg-slate-800 text-slate-300'
                    }`}>
                      {user.role}
                    </span>
                  </div>
                  <div className="text-slate-400 font-mono text-[11px] truncate">{user.email}</div>
                  <div className="pt-2 border-t border-slate-900 flex items-center justify-between text-slate-500 text-[11px]">
                    <span>Atividade: {user.lastActive}</span>
                    <span className="text-emerald-400">2FA Ativo</span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Audit Logs Table */}
          <div className="rounded-xl border border-slate-800 bg-slate-900 overflow-hidden font-mono text-xs">
            <div className="px-4 py-3 bg-slate-950 border-b border-slate-800 flex items-center justify-between">
              <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                Trilha de Auditoria Imutável (Ações de Mitigação & Configuração)
              </h4>
              <span className="text-slate-500 text-[11px]">
                {auditLogs.length} eventos registrados
              </span>
            </div>
            <div className="overflow-x-auto max-h-[400px]">
              <table className="w-full text-left">
                <thead className="bg-slate-950 text-slate-500 text-[11px] border-b border-slate-800 uppercase sticky top-0">
                  <tr>
                    <th className="py-2.5 px-3">Timestamp</th>
                    <th className="py-2.5 px-3">Operador / Agente</th>
                    <th className="py-2.5 px-3">Ação Executada</th>
                    <th className="py-2.5 px-3">Alvo</th>
                    <th className="py-2.5 px-3">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 text-slate-300">
                  {auditLogs.map((log) => (
                    <tr key={log.id} className="hover:bg-slate-800/40">
                      <td className="py-2 px-3 text-slate-400 whitespace-nowrap">{log.timestamp}</td>
                      <td className="py-2 px-3 text-cyan-300 font-semibold truncate max-w-xs">{log.operator}</td>
                      <td className="py-2 px-3 font-sans text-slate-200">{log.action}</td>
                      <td className="py-2 px-3 text-slate-400 truncate max-w-xs">{log.target}</td>
                      <td className="py-2 px-3">
                        <span className={`text-[10px] font-bold uppercase px-1.5 py-0.2 rounded ${
                          log.status === 'success' ? 'text-emerald-400 bg-emerald-950/60' : 'text-amber-400 bg-amber-950/60'
                        }`}>
                          {log.status}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
