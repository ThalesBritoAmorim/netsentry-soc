import React, { useState } from 'react';
import { Shield, Radio, Terminal, Cpu, Server, CheckCircle2, AlertCircle, Settings, Bot } from 'lucide-react';

export type NavTab = 'dashboard' | 'devices' | 'traffic' | 'deploy' | 'reports' | 'ai-integrations';

interface NavbarProps {
  activeTab: NavTab;
  onTabChange: (tab: NavTab) => void;
  autonomousMode: boolean;
  onToggleAutonomous: (enabled: boolean) => void;
  onOpenSimModal: () => void;
  isLiveKaliConnected?: boolean;
  kaliHostUrl?: string;
  onSetKaliHostUrl?: (url: string) => void;
  onOpenTerminal?: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  activeTab,
  onTabChange,
  autonomousMode,
  onToggleAutonomous,
  onOpenSimModal,
  isLiveKaliConnected,
  kaliHostUrl = 'http://localhost:8080',
  onSetKaliHostUrl,
  onOpenTerminal
}) => {
  const [showConfig, setShowConfig] = useState(false);
  const [inputUrl, setInputUrl] = useState(kaliHostUrl);

  const handleSaveUrl = (e: React.FormEvent) => {
    e.preventDefault();
    if (onSetKaliHostUrl) onSetKaliHostUrl(inputUrl);
    setShowConfig(false);
  };

  return (
    <header className="border-b border-slate-800 bg-slate-950/90 backdrop-blur-md sticky top-0 z-40">
      <div className="max-w-[1600px] mx-auto px-3 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between gap-8 h-16">
          {/* Zone 1: Single Brand Wordmark Element */}
          <div className="flex items-center gap-3 shrink-0">
            <div className="w-8 h-8 rounded-lg bg-cyan-950 border border-cyan-800 flex items-center justify-center text-cyan-400">
              <Shield className="w-4 h-4" />
            </div>
            <span className="text-base font-bold tracking-tight text-slate-100 whitespace-nowrap">
              NetSentry Kali SOC
            </span>
            <span className="hidden sm:inline-block text-xs text-slate-500 font-mono">
              v2.4
            </span>
          </div>

          {/* Zone 2: 5 Concise Single-Line Navigation Links */}
          <nav className="hidden md:flex items-center gap-6 text-sm font-medium text-slate-400">
            <button
              onClick={() => onTabChange('dashboard')}
              className={`whitespace-nowrap transition-colors pb-0.5 ${
                activeTab === 'dashboard'
                  ? 'text-cyan-400 border-b-2 border-cyan-400'
                  : 'hover:text-slate-200'
              }`}
            >
              Visão Geral
            </button>
            <button
              onClick={() => onTabChange('devices')}
              className={`whitespace-nowrap transition-colors pb-0.5 ${
                activeTab === 'devices'
                  ? 'text-cyan-400 border-b-2 border-cyan-400'
                  : 'hover:text-slate-200'
              }`}
            >
              Dispositivos & Mapa
            </button>
            <button
              onClick={() => onTabChange('traffic')}
              className={`whitespace-nowrap transition-colors pb-0.5 ${
                activeTab === 'traffic'
                  ? 'text-cyan-400 border-b-2 border-cyan-400'
                  : 'hover:text-slate-200'
              }`}
            >
              Tráfego & Anomalias
            </button>
            <button
              onClick={() => onTabChange('deploy')}
              className={`whitespace-nowrap transition-colors pb-0.5 ${
                activeTab === 'deploy'
                  ? 'text-cyan-400 border-b-2 border-cyan-400'
                  : 'hover:text-slate-200'
              }`}
            >
              Deploy Portainer / Kali
            </button>
            <button
              onClick={() => onTabChange('reports')}
              className={`whitespace-nowrap transition-colors pb-0.5 ${
                activeTab === 'reports'
                  ? 'text-cyan-400 border-b-2 border-cyan-400'
                  : 'hover:text-slate-200'
              }`}
            >
              Relatórios & Backups
            </button>
            <button
              onClick={() => onTabChange('ai-integrations')}
              className={`whitespace-nowrap transition-colors pb-0.5 flex items-center gap-1.5 ${
                activeTab === 'ai-integrations'
                  ? 'text-cyan-400 border-b-2 border-cyan-400'
                  : 'hover:text-slate-200'
              }`}
            >
              <Bot className="w-3.5 h-3.5" />
              <span>IA & Modelos</span>
            </button>
          </nav>

          {/* Zone 3: 1 Primary Action Area */}
          <div className="flex items-center gap-3 shrink-0">
            {/* Real Kali Connection Status Badge */}
            <div className="relative">
              <button
                onClick={() => setShowConfig(!showConfig)}
                className={`hidden lg:flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-mono border transition-all ${
                  isLiveKaliConnected
                    ? 'bg-emerald-950/80 border-emerald-700 text-emerald-300'
                    : 'bg-slate-900 border-slate-700 text-slate-400 hover:text-slate-200'
                }`}
                title="Status da conexão direta com o agente do Kali Linux"
              >
                {isLiveKaliConnected ? (
                  <>
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                    <span>KALI REAL: CONECTADO</span>
                  </>
                ) : (
                  <>
                    <Server className="w-3.5 h-3.5 text-slate-500" />
                    <span>KALI: CONECTAR HOST</span>
                  </>
                )}
                <Settings className="w-3 h-3 text-slate-500 ml-0.5" />
              </button>

              {/* Host URL Configuration Popover */}
              {showConfig && (
                <div className="absolute right-0 mt-2 w-72 p-3 bg-slate-900 border border-slate-800 rounded-lg shadow-2xl z-50 text-xs animate-fadeIn">
                  <div className="font-semibold text-slate-200 mb-1">
                    Conexão ao Host Kali Linux
                  </div>
                  <p className="text-slate-400 text-[11px] mb-2 leading-relaxed">
                    URL da API do Daemon NetSentry em execução no Kali (porta 8080):
                  </p>
                  <form onSubmit={handleSaveUrl} className="space-y-2">
                    <input
                      type="text"
                      value={inputUrl}
                      onChange={(e) => setInputUrl(e.target.value)}
                      placeholder="http://localhost:8080"
                      className="w-full px-2 py-1 bg-slate-950 border border-slate-700 rounded text-slate-200 font-mono text-xs focus:outline-none focus:border-cyan-500"
                    />
                    <div className="flex items-center justify-between pt-1">
                      <span className="text-[10px] text-slate-500">
                        {isLiveKaliConnected ? 'Status: Online' : 'Status: Aguardando'}
                      </span>
                      <button
                        type="submit"
                        className="px-2.5 py-1 rounded bg-cyan-500 text-slate-950 font-semibold text-[11px] hover:bg-cyan-400"
                      >
                        Salvar & Conectar
                      </button>
                    </div>
                  </form>
                </div>
              )}
            </div>

            {/* Autonomous defence mode toggle */}
            <button
              onClick={() => onToggleAutonomous(!autonomousMode)}
              className={`hidden sm:flex items-center gap-2 px-3 py-1.5 rounded-md text-xs font-mono border transition-all ${
                autonomousMode
                  ? 'bg-emerald-950/60 border-emerald-800 text-emerald-300'
                  : 'bg-slate-900 border-slate-700 text-slate-400 hover:text-slate-200'
              }`}
              title="Ativar/Desativar execução autônoma de mitigação no netfilter"
            >
              <Cpu className="w-3.5 h-3.5" />
              <span>{autonomousMode ? 'Defesa: ATIVA' : 'Supervisionada'}</span>
            </button>

            {/* Direct Kali Terminal Drawer Trigger */}
            {onOpenTerminal && (
              <button
                onClick={onOpenTerminal}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-mono bg-slate-900 border border-slate-700 text-slate-300 hover:text-cyan-300 hover:border-cyan-700 transition-colors"
                title="Abrir Terminal Integrado do Kali Linux"
              >
                <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                <span className="hidden sm:inline">Terminal Kali</span>
              </button>
            )}

            {/* Attack simulator CTA */}
            <button
              onClick={onOpenSimModal}
              className="px-3.5 py-1.5 text-xs font-semibold text-slate-950 bg-cyan-400 rounded-md hover:bg-cyan-300 transition-colors whitespace-nowrap shrink-0 shadow-sm shadow-cyan-950 flex items-center gap-1.5"
            >
              <Radio className="w-3.5 h-3.5" />
              <span>Simulador</span>
            </button>
          </div>
        </div>

        {/* Mobile Navigation Row */}
        <div className="flex md:hidden items-center justify-between overflow-x-auto py-2.5 border-t border-slate-900 text-xs font-medium text-slate-400 gap-4">
          <button
            onClick={() => onTabChange('dashboard')}
            className={`whitespace-nowrap ${activeTab === 'dashboard' ? 'text-cyan-400 font-bold' : ''}`}
          >
            Visão Geral
          </button>
          <button
            onClick={() => onTabChange('devices')}
            className={`whitespace-nowrap ${activeTab === 'devices' ? 'text-cyan-400 font-bold' : ''}`}
          >
            Dispositivos
          </button>
          <button
            onClick={() => onTabChange('traffic')}
            className={`whitespace-nowrap ${activeTab === 'traffic' ? 'text-cyan-400 font-bold' : ''}`}
          >
            Tráfego
          </button>
          <button
            onClick={() => onTabChange('deploy')}
            className={`whitespace-nowrap ${activeTab === 'deploy' ? 'text-cyan-400 font-bold' : ''}`}
          >
            Portainer & Kali
          </button>
          <button
            onClick={() => onTabChange('reports')}
            className={`whitespace-nowrap ${activeTab === 'reports' ? 'text-cyan-400 font-bold' : ''}`}
          >
            Relatórios
          </button>
          <button
            onClick={() => onTabChange('ai-integrations')}
            className={`whitespace-nowrap ${activeTab === 'ai-integrations' ? 'text-cyan-400 font-bold' : ''}`}
          >
            IA & Modelos
          </button>
        </div>
      </div>
    </header>
  );
};
