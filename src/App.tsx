/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect } from 'react';
import { networkEngine, NetworkEngineState } from './services/networkEngine';
import { ThreatAlert, ThreatCategory, DeviceTrustLevel } from './types';
import { Navbar, NavTab } from './components/Navbar';
import { DashboardView } from './components/DashboardView';
import { DevicesView } from './components/DevicesView';
import { TrafficLogsView } from './components/TrafficLogsView';
import { WebScannerView } from './components/WebScannerView';
import { NetworkAuditView } from './components/NetworkAuditView';
import { PortainerDeployView } from './components/PortainerDeployView';
import { ReportsBackupView } from './components/ReportsBackupView';
import { AIIntegrationsView } from './components/AIIntegrationsView';
import { AnalysisParametersView } from './components/AnalysisParametersView';
import { MitigationModal } from './components/MitigationModal';
import { AnomalySimulatorModal } from './components/AnomalySimulatorModal';
import { KaliTerminalDrawer } from './components/KaliTerminalDrawer';
import { AIForensicModal, AIForensicTargetType } from './components/AIForensicModal';
import { CheckCircle2, ShieldAlert } from 'lucide-react';

export default function App() {
  const [engineState, setEngineState] = useState<NetworkEngineState>(networkEngine.getState());
  const [activeTab, setActiveTab] = useState<NavTab>('dashboard');
  const [selectedAlertForPlaybook, setSelectedAlertForPlaybook] = useState<ThreatAlert | null>(null);
  const [isSimModalOpen, setIsSimModalOpen] = useState(false);
  const [toastMessage, setToastMessage] = useState<{ text: string; type: 'success' | 'alert' } | null>(null);

  // AI Forensic Modal State
  const [isAIForensicOpen, setIsAIForensicOpen] = useState(false);
  const [aiForensicTargetType, setAiForensicTargetType] = useState<AIForensicTargetType>('posture');
  const [aiForensicTargetData, setAiForensicTargetData] = useState<any>(null);

  const handleOpenAIForensic = (type: AIForensicTargetType, data?: any) => {
    setAiForensicTargetType(type);
    setAiForensicTargetData(data);
    setIsAIForensicOpen(true);
  };

  // Terminal Kali State
  const [isTerminalOpen, setIsTerminalOpen] = useState(false);
  const [terminalCommand, setTerminalCommand] = useState('sudo nmap -sV -sC -O -Pn 192.168.1.1');
  const [terminalOutput, setTerminalOutput] = useState('');
  const [isTerminalRunning, setIsTerminalRunning] = useState(false);

  useEffect(() => {
    const unsubscribe = networkEngine.subscribe((newState) => {
      setEngineState({ ...newState });
    });
    return () => unsubscribe();
  }, []);

  const showToast = (text: string, type: 'success' | 'alert' = 'success') => {
    setToastMessage({ text, type });
    setTimeout(() => {
      setToastMessage(null);
    }, 3500);
  };

  const handleApplyMitigation = (alertId: string) => {
    networkEngine.applyMitigation(alertId);
    showToast('Mitigação executada com sucesso no kernel Netfilter (Iptables)!', 'success');
    if (selectedAlertForPlaybook && selectedAlertForPlaybook.id === alertId) {
      setSelectedAlertForPlaybook({
        ...selectedAlertForPlaybook,
        status: 'mitigated',
        playbook: {
          ...selectedAlertForPlaybook.playbook,
          applied: true,
          appliedAt: new Date().toLocaleTimeString('pt-BR')
        }
      });
    }
  };

  const handleRollbackMitigation = (alertId: string) => {
    networkEngine.rollbackMitigation(alertId);
    showToast('Regra de mitigação revertida com sucesso no firewall.', 'alert');
    if (selectedAlertForPlaybook && selectedAlertForPlaybook.id === alertId) {
      setSelectedAlertForPlaybook({
        ...selectedAlertForPlaybook,
        status: 'active',
        playbook: {
          ...selectedAlertForPlaybook.playbook,
          applied: false,
          appliedAt: undefined
        }
      });
    }
  };

  const handleUnblockHost = async (ip: string = '192.168.0.156') => {
    await networkEngine.unblockHost(ip);
    showToast(`Host Kali Linux (${ip}) desbloqueado e adicionado à Whitelist! Regras DROP removidas do Netfilter.`, 'success');
  };

  const handleSimulateAttack = (category: ThreatCategory) => {
    networkEngine.simulateAttack(category);
    showToast(`Anomalia [${category}] injetada no sniffer! Verificando resposta autônoma...`, 'alert');
  };

  const handleSetTrustLevel = (deviceId: string, level: DeviceTrustLevel) => {
    networkEngine.setDeviceTrust(deviceId, level);
    showToast(`Confiabilidade do dispositivo atualizada para ${level}.`, 'success');
  };

  const handleScanSubnet = (deep: boolean = false) => {
    networkEngine.scanSubnet(deep);
    showToast(
      deep 
        ? 'Varredura Profunda Nmap (DNS + NetBIOS + Portas) iniciada no Kali Linux!' 
        : 'Varredura Rápida ARP iniciada no Kali Linux. Dispositivos atualizados.', 
      'success'
    );
  };

  const handleSetDeviceAlias = (deviceId: string, alias: string) => {
    networkEngine.setDeviceAlias(deviceId, alias);
    showToast(`Identificação/Alias do host atualizado com sucesso!`, 'success');
  };

  const handleToggleRule = (ruleId: string, enabled: boolean) => {
    networkEngine.toggleRule(ruleId, enabled);
    showToast(`Regra ${ruleId} ${enabled ? 'ativada' : 'desativada'}.`, 'success');
  };

  const handleTriggerBackup = () => {
    const bk = networkEngine.triggerManualBackup();
    showToast(`Backup PostgreSQL ${bk.filename} criado e verificado!`, 'success');
  };

  // Run command on Kali Linux Host Terminal
  const handleRunKaliCommand = async (cmd: string) => {
    setIsTerminalRunning(true);
    setTerminalCommand(cmd);
    setIsTerminalOpen(true);
    setTerminalOutput(`[NetSentry Agent] Conectando ao terminal do Kali Linux...\n$ ${cmd}\n`);

    try {
      const res = await networkEngine.executeKaliCommand(cmd);
      setTerminalOutput((prev) => `${prev}\n${res.output || 'Comando concluído com sucesso.'}`);
      if (res.success) {
        showToast('Comando enviado e executado no Kali Linux!', 'success');
      } else {
        showToast('Comando concluído com observações.', 'alert');
      }
    } catch (err: any) {
      setTerminalOutput((prev) => `${prev}\nErro ao executar comando: ${err.message}`);
      showToast('Erro de comunicação com o host Kali.', 'alert');
    } finally {
      setIsTerminalRunning(false);
    }
  };

  const handleOpenTerminalWithCommand = (cmd: string) => {
    setTerminalCommand(cmd);
    setIsTerminalOpen(true);
    handleRunKaliCommand(cmd);
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-cyan-500/20 selection:text-cyan-200 overflow-x-hidden">
      {/* Top Bar */}
      <Navbar
        activeTab={activeTab}
        onTabChange={setActiveTab}
        autonomousMode={engineState.metrics.autonomousMode}
        onToggleAutonomous={(enabled) => {
          networkEngine.toggleAutonomousMode(enabled);
          showToast(
            enabled ? 'Modo autônomo ativado: mitigações críticas serão executadas instantaneamente!' : 'Modo supervisionado ativo.',
            enabled ? 'success' : 'alert'
          );
        }}
        onOpenSimModal={() => setIsSimModalOpen(true)}
        isLiveKaliConnected={engineState.metrics.isLiveKaliConnected}
        kaliHostUrl={engineState.metrics.kaliHostUrl}
        onSetKaliHostUrl={(url) => {
          networkEngine.setKaliHostUrl(url);
          showToast(`URL do Agente Kali definida como ${url}. Conectando...`, 'alert');
        }}
        onOpenTerminal={() => setIsTerminalOpen(true)}
      />

      {/* Main Workspace Viewport */}
      <main className="flex-1 max-w-[1600px] w-full mx-auto px-3 sm:px-6 lg:px-8 py-5 min-w-0">
        {activeTab === 'dashboard' && (
          <DashboardView
            metrics={engineState.metrics}
            devices={engineState.devices}
            alerts={engineState.alerts}
            trafficFlows={engineState.trafficFlows}
            onOpenPlaybook={(alert) => setSelectedAlertForPlaybook(alert)}
            onApplyMitigation={handleApplyMitigation}
            onRollbackMitigation={handleRollbackMitigation}
            onSimulateAttack={handleSimulateAttack}
            onNavigateToDevices={() => setActiveTab('devices')}
            onNavigateToDeploy={() => setActiveTab('deploy')}
            onOpenKaliTerminal={handleOpenTerminalWithCommand}
            onUnblockHost={handleUnblockHost}
            onOpenAIForensic={handleOpenAIForensic}
          />
        )}

        {activeTab === 'devices' && (
          <DevicesView
            devices={engineState.devices}
            onSetTrustLevel={handleSetTrustLevel}
            onScanSubnet={handleScanSubnet}
            onSetDeviceAlias={handleSetDeviceAlias}
            onOpenKaliTerminal={handleOpenTerminalWithCommand}
            onOpenAIForensic={handleOpenAIForensic}
          />
        )}

        {activeTab === 'traffic' && (
          <TrafficLogsView
            flows={engineState.trafficFlows}
            rules={engineState.rules}
            isStreaming={engineState.isStreaming}
            onToggleStreaming={() => networkEngine.toggleStreaming()}
            onToggleRule={handleToggleRule}
            onOpenAIForensic={handleOpenAIForensic}
          />
        )}

        {activeTab === 'web-scanner' && (
          <WebScannerView
            onOpenKaliTerminal={handleOpenTerminalWithCommand}
            onToast={showToast}
          />
        )}

        {activeTab === 'network-audit' && (
          <NetworkAuditView
            devices={engineState.devices}
            onOpenKaliTerminal={handleOpenTerminalWithCommand}
            onToast={showToast}
            onOpenAIForensic={handleOpenAIForensic}
            onScanSubnet={handleScanSubnet}
          />
        )}

        {activeTab === 'deploy' && <PortainerDeployView />}

        {activeTab === 'reports' && (
          <ReportsBackupView
            alerts={engineState.alerts}
            devices={engineState.devices}
            backups={engineState.backups}
            auditLogs={engineState.auditLogs}
            onTriggerBackup={handleTriggerBackup}
          />
        )}

        {activeTab === 'ai-integrations' && (
          <AIIntegrationsView
            alerts={engineState.alerts}
            metrics={engineState.metrics}
            devices={engineState.devices}
            onOpenKaliTerminal={handleOpenTerminalWithCommand}
            onToast={showToast}
          />
        )}

        {activeTab === 'parameters' && (
          <AnalysisParametersView
            onToast={showToast}
            onOpenKaliTerminal={handleOpenTerminalWithCommand}
          />
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-900 bg-slate-950 py-4 text-xs text-slate-500">
        <div className="max-w-[1600px] mx-auto px-3 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-2">
          <div>
            NetSentry Kali SOC & Daemon Autônomo · PostgreSQL 16 · Portainer Stack
          </div>
          <div className="flex items-center gap-4 text-slate-400">
            <span>Interface: <code className="text-cyan-400 font-mono">eth0 (promisc)</code></span>
            <span aria-hidden="true">·</span>
            <span>Kernel Netfilter: <span className="text-emerald-400">Ativo</span></span>
          </div>
        </div>
      </footer>

      {/* Modals & Terminal Drawer */}
      <MitigationModal
        alert={selectedAlertForPlaybook}
        onClose={() => setSelectedAlertForPlaybook(null)}
        onApplyMitigation={handleApplyMitigation}
        onRollbackMitigation={handleRollbackMitigation}
        onOpenKaliTerminal={handleOpenTerminalWithCommand}
      />

      <AnomalySimulatorModal
        isOpen={isSimModalOpen}
        onClose={() => setIsSimModalOpen(false)}
        onSimulate={handleSimulateAttack}
        autonomousMode={engineState.metrics.autonomousMode}
      />

      <AIForensicModal
        isOpen={isAIForensicOpen}
        onClose={() => setIsAIForensicOpen(false)}
        targetType={aiForensicTargetType}
        targetData={aiForensicTargetData}
        metrics={engineState.metrics}
        devices={engineState.devices}
        onOpenKaliTerminal={handleOpenTerminalWithCommand}
        onApplyMitigation={handleApplyMitigation}
        onToast={showToast}
      />

      <KaliTerminalDrawer
        isOpen={isTerminalOpen}
        onClose={() => setIsTerminalOpen(false)}
        command={terminalCommand}
        output={terminalOutput}
        isRunning={isTerminalRunning}
        onRunCommand={handleRunKaliCommand}
        isLiveKaliConnected={engineState.metrics.isLiveKaliConnected}
      />

      {/* Real-time Toast Notifications */}
      {toastMessage && (
        <div className="fixed bottom-6 right-6 z-50 animate-slideUp">
          <div className={`flex items-center gap-2.5 px-4 py-2.5 rounded-lg shadow-xl border text-xs font-medium ${
            toastMessage.type === 'success'
              ? 'bg-slate-900 border-emerald-800 text-emerald-300'
              : 'bg-slate-900 border-cyan-800 text-cyan-300'
          }`}>
            {toastMessage.type === 'success' ? (
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
            ) : (
              <ShieldAlert className="w-4 h-4 text-cyan-400 shrink-0" />
            )}
            <span>{toastMessage.text}</span>
          </div>
        </div>
      )}
    </div>
  );
}
