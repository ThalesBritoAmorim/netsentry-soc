import React, { useState } from 'react';
import { 
  NetworkDevice,
  SystemMetrics,
  AIProviderId, 
  AIProviderConfig, 
  AISettings, 
  ThreatAlert 
} from '../types';
import { 
  aiService, 
  SUPPORTED_AI_PROVIDERS 
} from '../services/aiService';
import { 
  Bot, 
  Sparkles, 
  CheckCircle2, 
  AlertCircle, 
  Shield, 
  Lock, 
  Radio, 
  Terminal, 
  Server, 
  Play, 
  Cpu, 
  Key, 
  Eye, 
  EyeOff, 
  Check, 
  Copy, 
  RefreshCw, 
  ExternalLink,
  ShieldCheck,
  Zap,
  Info
} from 'lucide-react';

interface AIIntegrationsViewProps {
  alerts: ThreatAlert[];
  metrics?: SystemMetrics;
  devices?: NetworkDevice[];
  onOpenKaliTerminal?: (cmd: string) => void;
  onToast: (msg: string, type: 'success' | 'alert') => void;
}

export const AIIntegrationsView: React.FC<AIIntegrationsViewProps> = ({
  alerts,
  metrics,
  devices,
  onOpenKaliTerminal,
  onToast
}) => {
  const [settings, setSettings] = useState<AISettings>(aiService.getSettings());
  const [providers, setProviders] = useState<AIProviderConfig[]>(SUPPORTED_AI_PROVIDERS);
  const [testingProvider, setTestingProvider] = useState<AIProviderId | null>(null);
  const [testResults, setTestResults] = useState<Record<string, { success: boolean; latency: number; msg: string }>>({});
  const [ollamaUrlInput, setOllamaUrlInput] = useState(settings.ollamaEndpoint);

  // Playground state
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [aiOutput, setAiOutput] = useState<{
    analysis?: string;
    riskLevel?: string;
    mitreTechnique?: string;
    validatedCommand?: string;
    providerUsed?: string;
    modelUsed?: string;
    recommendedActions?: string[];
  } | null>(null);
  const [copiedCmd, setCopiedCmd] = useState(false);

  const activeProviderConfig = providers.find(p => p.id === settings.activeProvider) || providers[0];

  const handleSelectProvider = (providerId: AIProviderId) => {
    const prov = providers.find(p => p.id === providerId);
    if (!prov) return;

    if (settings.strictOfflineMode && prov.type === 'cloud') {
      onToast('Modo Estrito Offline ativo. Desative-o para selecionar provedores em nuvem.', 'alert');
      return;
    }

    const updated = aiService.saveSettings({
      activeProvider: providerId,
      selectedModel: prov.defaultModel
    });
    setSettings(updated);
    onToast(`Provedor de IA ativo alterado para ${prov.name} (${prov.defaultModel})`, 'success');
  };

  const handleSelectModel = (model: string) => {
    const updated = aiService.saveSettings({ selectedModel: model });
    setSettings(updated);
    onToast(`Modelo de inferência atualizado para ${model}`, 'success');
  };

  const handleToggleAnonymize = (enabled: boolean) => {
    const updated = aiService.saveSettings({ anonymizeNetworkData: enabled });
    setSettings(updated);
    onToast(
      enabled 
        ? 'Anonimização ativada: IPs privados e MACs serão mascarados antes do envio.' 
        : 'Anonimização desativada.', 
      'success'
    );
  };

  const handleToggleStrictOffline = (enabled: boolean) => {
    const changes: Partial<AISettings> = { strictOfflineMode: enabled };
    if (enabled && activeProviderConfig.type === 'cloud') {
      changes.activeProvider = 'ollama';
      changes.selectedModel = 'deepseek-r1:8b';
    }
    const updated = aiService.saveSettings(changes);
    setSettings(updated);
    onToast(
      enabled 
        ? 'Modo Estrito Offline ATIVADO: Apenas inferência local (Ollama) permitida. Zero saída para internet.' 
        : 'Modo Estrito Offline desativado.', 
      'alert'
    );
  };

  const handleSaveOllamaUrl = () => {
    const updated = aiService.saveSettings({ ollamaEndpoint: ollamaUrlInput });
    setSettings(updated);
    onToast(`Endpoint do Ollama salvo como: ${ollamaUrlInput}`, 'success');
    handleTestConnection('ollama');
  };

  const handleTestConnection = async (providerId: AIProviderId) => {
    setTestingProvider(providerId);
    try {
      const res = await aiService.testProviderConnection(providerId, ollamaUrlInput);
      setTestResults(prev => ({
        ...prev,
        [providerId]: {
          success: res.success,
          latency: res.latencyMs,
          msg: res.message
        }
      }));

      // Update provider status in state
      setProviders(prev => prev.map(p => {
        if (p.id === providerId) {
          return {
            ...p,
            status: res.success ? 'ready' : 'offline',
            latencyMs: res.latencyMs
          };
        }
        return p;
      }));

      onToast(res.message, res.success ? 'success' : 'alert');
    } catch (e: any) {
      setTestResults(prev => ({
        ...prev,
        [providerId]: {
          success: false,
          latency: 0,
          msg: e.message || 'Falha de comunicação.'
        }
      }));
    } finally {
      setTestingProvider(null);
    }
  };

  // Run AI threat analysis or live network posture analysis
  const handleRunAnalysis = async () => {
    setIsAnalyzing(true);
    setAiOutput(null);

    try {
      const activeAlert = alerts.find(a => a.status === 'active') || alerts[0];
      let res;
      if (activeAlert) {
        res = await aiService.analyzeThreat(activeAlert, metrics, devices);
      } else {
        // Zero alerts in network - analyze real live network posture
        res = await aiService.analyzeNetworkPosture(metrics, devices || []);
      }

      setAiOutput({
        analysis: res.analysis,
        riskLevel: res.riskLevel,
        mitreTechnique: res.mitreTechnique,
        validatedCommand: res.validatedIptablesCommand,
        providerUsed: res.providerUsed,
        modelUsed: res.modelUsed,
        recommendedActions: res.recommendedActions
      });
      onToast(`Análise concluída com sucesso via ${res.providerUsed} (${res.modelUsed})`, 'success');
    } catch (err: any) {
      onToast(`Erro ao gerar análise: ${err.message || 'Falha de comunicação'}`, 'alert');
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleCopyCommand = (cmd: string) => {
    navigator.clipboard.writeText(cmd);
    setCopiedCmd(true);
    setTimeout(() => setCopiedCmd(false), 2000);
    onToast('Comando copiado para a área de transferência!', 'success');
  };

  return (
    <div className="space-y-6">
      {/* 1. Header Banner */}
      <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-4 shadow-xl">
        <div className="flex items-start sm:items-center gap-3.5">
          <div className="p-3 rounded-xl bg-cyan-950/80 border border-cyan-800 text-cyan-400 shrink-0">
            <Bot className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center gap-2.5 flex-wrap">
              <h2 className="text-base sm:text-lg font-bold text-slate-100">
                Hub de Integrações de IA & Modelos SOC
              </h2>
              <span className={`text-[11px] font-mono px-2 py-0.5 rounded-full border flex items-center gap-1.5 ${
                activeProviderConfig.type === 'local'
                  ? 'bg-emerald-950 text-emerald-300 border-emerald-800 font-semibold'
                  : 'bg-cyan-950 text-cyan-300 border-cyan-800'
              }`}>
                <span className={`w-1.5 h-1.5 rounded-full ${activeProviderConfig.type === 'local' ? 'bg-emerald-400 animate-pulse' : 'bg-cyan-400'}`} />
                {activeProviderConfig.name} ({settings.selectedModel})
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-1 max-w-3xl leading-relaxed">
              Habilite e configure a IA de sua escolha para automatizar a triagem de ameaças, interpretar pacotes do sniffer e auditar regras de firewall no Kali Linux. Suporta APIs em nuvem e inferência 100% local/offline via Ollama.
            </p>
          </div>
        </div>

        {/* Global Air-Gap Badge */}
        <div className="shrink-0">
          <div className={`p-2.5 px-3 rounded-lg border text-xs flex items-center gap-2 ${
            settings.strictOfflineMode
              ? 'bg-emerald-950/40 border-emerald-800 text-emerald-300'
              : 'bg-slate-950 border-slate-800 text-slate-400'
          }`}>
            <Lock className={`w-4 h-4 ${settings.strictOfflineMode ? 'text-emerald-400' : 'text-slate-500'}`} />
            <div>
              <span className="font-semibold block">
                {settings.strictOfflineMode ? 'Modo Estrito Offline Ativo' : 'Modo Híbrido Flexível'}
              </span>
              <span className="text-[10px] text-slate-400">
                {settings.strictOfflineMode ? 'Zero saída para a internet' : 'Nuvem ou Local permitidos'}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* 2. Provider Selection Grid */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
            <Cpu className="w-4 h-4 text-cyan-400" />
            <span>Provedores de Inteligência Artificial Suportados</span>
          </h3>
          <span className="text-xs text-slate-400">
            Clique em um provedor para definir como motor ativo do SOC
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {providers.map((p) => {
            const isActive = settings.activeProvider === p.id;
            const isLocal = p.type === 'local';
            const isChecking = testingProvider === p.id;
            const testResult = testResults[p.id];

            return (
              <div
                key={p.id}
                className={`p-4 rounded-xl border transition-all flex flex-col justify-between relative ${
                  isActive 
                    ? isLocal
                      ? 'bg-emerald-950/20 border-emerald-600/90 shadow-lg shadow-emerald-950/40 ring-1 ring-emerald-500/50'
                      : 'bg-cyan-950/20 border-cyan-500/90 shadow-lg shadow-cyan-950/40 ring-1 ring-cyan-500/50'
                    : 'bg-slate-900 border-slate-800 hover:border-slate-700'
                }`}
              >
                {/* Top Badge & Vendor */}
                <div>
                  <div className="flex items-start justify-between gap-2 mb-2">
                    <div className="flex items-center gap-2.5">
                      <div className={`p-2 rounded-lg border ${
                        isLocal
                          ? 'bg-emerald-950 text-emerald-400 border-emerald-800'
                          : 'bg-slate-950 text-cyan-400 border-slate-800'
                      }`}>
                        {isLocal ? <Server className="w-4 h-4" /> : <Sparkles className="w-4 h-4" />}
                      </div>
                      <div>
                        <div className="flex items-center gap-2">
                          <h4 className="text-sm font-bold text-slate-100">{p.name}</h4>
                          {isLocal && (
                            <span className="text-[10px] uppercase font-mono px-1.5 py-0.2 rounded font-bold bg-emerald-950 text-emerald-300 border border-emerald-800">
                              100% Local / Offline
                            </span>
                          )}
                          {!isLocal && (
                            <span className="text-[10px] uppercase font-mono px-1.5 py-0.2 rounded text-slate-400 bg-slate-950 border border-slate-800">
                              Nuvem (HTTPS)
                            </span>
                          )}
                        </div>
                        <span className="text-[11px] text-slate-500">{p.vendor}</span>
                      </div>
                    </div>

                    {isActive && (
                      <span className={`text-[11px] font-semibold px-2 py-0.5 rounded-full flex items-center gap-1 ${
                        isLocal 
                          ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40' 
                          : 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                      }`}>
                        <CheckCircle2 className="w-3 h-3" />
                        Ativo
                      </span>
                    )}
                  </div>

                  <p className="text-xs text-slate-300 leading-relaxed mb-3">
                    {p.description}
                  </p>

                  {/* Model Selector within Provider */}
                  <div className="mb-3 p-2.5 rounded-lg bg-slate-950 border border-slate-800/80 space-y-1.5">
                    <div className="flex items-center justify-between text-[11px] text-slate-400">
                      <span>Modelo de Inferência:</span>
                      {p.latencyMs && (
                        <span className="font-mono text-emerald-400">~{p.latencyMs}ms latência</span>
                      )}
                    </div>
                    <select
                      value={isActive ? settings.selectedModel : p.defaultModel}
                      onChange={(e) => {
                        if (isActive) {
                          handleSelectModel(e.target.value);
                        } else {
                          handleSelectProvider(p.id);
                          handleSelectModel(e.target.value);
                        }
                      }}
                      className="w-full bg-slate-900 border border-slate-800 rounded px-2.5 py-1 text-xs text-slate-200 font-mono focus:outline-none focus:border-cyan-500"
                    >
                      {p.availableModels.map((m) => (
                        <option key={m} value={m}>
                          {m}
                        </option>
                      ))}
                    </select>
                  </div>

                  {/* Test Output message if available */}
                  {testResult && (
                    <div className={`p-2 rounded text-[11px] mb-3 flex items-start gap-1.5 ${
                      testResult.success 
                        ? 'bg-emerald-950/40 border border-emerald-800 text-emerald-300' 
                        : 'bg-rose-950/40 border border-rose-800 text-rose-300'
                    }`}>
                      {testResult.success ? <CheckCircle2 className="w-3.5 h-3.5 shrink-0 mt-0.5" /> : <AlertCircle className="w-3.5 h-3.5 shrink-0 mt-0.5" />}
                      <span>{testResult.msg}</span>
                    </div>
                  )}
                </div>

                {/* Bottom Actions */}
                <div className="flex items-center gap-2 pt-2 border-t border-slate-800/70 mt-2">
                  <button
                    onClick={() => handleSelectProvider(p.id)}
                    disabled={isActive}
                    className={`flex-1 py-1.5 rounded-lg text-xs font-semibold transition-all ${
                      isActive
                        ? 'bg-slate-800/60 text-slate-400 cursor-default'
                        : isLocal
                          ? 'bg-emerald-500 hover:bg-emerald-400 text-slate-950 shadow-sm'
                          : 'bg-cyan-500 hover:bg-cyan-400 text-slate-950 shadow-sm'
                    }`}
                  >
                    {isActive ? 'Motor Selecionado' : 'Definir como Ativo'}
                  </button>

                  <button
                    onClick={() => handleTestConnection(p.id)}
                    disabled={isChecking}
                    className="p-1.5 px-2.5 rounded-lg border border-slate-800 bg-slate-950 hover:bg-slate-800 text-xs font-medium text-slate-300 flex items-center gap-1.5 transition-colors"
                    title="Testar resposta e latência deste provedor"
                  >
                    <RefreshCw className={`w-3.5 h-3.5 ${isChecking ? 'animate-spin text-cyan-400' : 'text-slate-400'}`} />
                    <span className="hidden sm:inline">Testar</span>
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* 3. Security, Privacy & Local Endpoint Configurations */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Privacy & Air-gap Controls */}
        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-4">
          <div className="flex items-center gap-2 text-sm font-semibold text-slate-200">
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
            <span>Privacidade & Controle de Tráfego de IA</span>
          </div>

          <div className="space-y-3 text-xs">
            {/* Anonymization Toggle */}
            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 flex items-start justify-between gap-3">
              <div>
                <div className="font-semibold text-slate-200 flex items-center gap-1.5">
                  <Key className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Anonimização de IPs e MACs da Rede Local</span>
                </div>
                <p className="text-slate-400 text-[11px] mt-1 leading-relaxed">
                  Substitui endereços IP privados (<code className="text-cyan-400">192.168.x.x</code>) e endereços físicos MAC por tokens sintéticos antes de qualquer consulta externa, garantindo sigilo da topologia.
                </p>
              </div>
              <button
                onClick={() => handleToggleAnonymize(!settings.anonymizeNetworkData)}
                className={`w-11 h-6 rounded-full transition-colors relative shrink-0 ${
                  settings.anonymizeNetworkData ? 'bg-cyan-500' : 'bg-slate-800'
                }`}
              >
                <span className={`w-4 h-4 rounded-full bg-white absolute top-1 transition-transform ${
                  settings.anonymizeNetworkData ? 'right-1' : 'left-1'
                }`} />
              </button>
            </div>

            {/* Strict Offline Toggle */}
            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 flex items-start justify-between gap-3">
              <div>
                <div className="font-semibold text-slate-200 flex items-center gap-1.5">
                  <Lock className="w-3.5 h-3.5 text-emerald-400" />
                  <span>Modo Estrito 100% Offline (Air-Gapped)</span>
                </div>
                <p className="text-slate-400 text-[11px] mt-1 leading-relaxed">
                  Bloqueia qualquer requisição de IA para fora da máquina local. Força o uso exclusivo do Ollama/DeepSeek rodando no Kali Linux, impedindo saída de pacotes para a internet.
                </p>
              </div>
              <button
                onClick={() => handleToggleStrictOffline(!settings.strictOfflineMode)}
                className={`w-11 h-6 rounded-full transition-colors relative shrink-0 ${
                  settings.strictOfflineMode ? 'bg-emerald-500' : 'bg-slate-800'
                }`}
              >
                <span className={`w-4 h-4 rounded-full bg-white absolute top-1 transition-transform ${
                  settings.strictOfflineMode ? 'right-1' : 'left-1'
                }`} />
              </button>
            </div>
          </div>
        </div>

        {/* Local Ollama Endpoint & Kali Configuration */}
        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-4">
          <div className="flex items-center gap-2 text-sm font-semibold text-slate-200">
            <Server className="w-4 h-4 text-cyan-400" />
            <span>Configuração do Endpoint Ollama (Host Kali)</span>
          </div>

          <div className="space-y-3 text-xs">
            <div>
              <label className="text-[11px] text-slate-400 font-medium block mb-1">
                URL da API REST do Ollama / LM Studio Local:
              </label>
              <div className="flex items-center gap-2">
                <input
                  type="text"
                  value={ollamaUrlInput}
                  onChange={(e) => setOllamaUrlInput(e.target.value)}
                  placeholder="http://127.0.0.1:11434"
                  className="flex-1 bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-200 font-mono focus:outline-none focus:border-cyan-500"
                />
                <button
                  onClick={handleSaveOllamaUrl}
                  className="px-3 py-1.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-xs transition-colors shrink-0"
                >
                  Salvar
                </button>
              </div>
              <p className="text-[11px] text-slate-500 mt-1">
                Porta padrão do Ollama: <code className="text-slate-300">11434</code>. Se estiver em outro computador da rede, use o IP (ex: <code className="text-slate-300">http://192.168.1.50:11434</code>).
              </p>
            </div>

            <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800/80 font-mono text-[11px] text-slate-400 space-y-1">
              <span className="text-cyan-400 block font-bold font-sans">Comandos para iniciar no terminal do Kali:</span>
              <div className="text-slate-300">$ curl -fsSL https://ollama.com/install.sh | sh</div>
              <div className="text-emerald-400">$ ollama run deepseek-r1:8b  # ou llama3.3:8b</div>
            </div>
          </div>
        </div>
      </div>

      {/* 4. Interactive AI SOC Forensic Lab */}
      <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-4 shadow-xl">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h3 className="text-sm sm:text-base font-semibold text-slate-100 flex items-center gap-2">
              <Sparkles className="w-4 h-4 text-cyan-400" />
              <span>Laboratório Forense de IA em Tempo Real</span>
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Valide o raciocínio do motor ativo sobre os alertas capturados pelo sniffer do Kali Linux.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleRunAnalysis}
              disabled={isAnalyzing}
              className="flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold text-slate-950 bg-cyan-400 hover:bg-cyan-300 transition-all shadow-md active:scale-95 disabled:opacity-50"
            >
              {isAnalyzing ? (
                <>
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  <span>Consultando {activeProviderConfig.name}...</span>
                </>
              ) : (
                <>
                  <Zap className="w-3.5 h-3.5 fill-slate-950" />
                  <span>
                    {alerts.length > 0 
                      ? `Analisar Alerta Ativo com ${activeProviderConfig.name}` 
                      : `Analisar Postura da Rede com ${activeProviderConfig.name}`}
                  </span>
                </>
              )}
            </button>
          </div>
        </div>

        {/* AI Forensic Response Box */}
        {aiOutput ? (
          <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-3.5 animate-fadeIn">
            {/* Meta bar */}
            <div className="flex flex-wrap items-center justify-between gap-2 pb-2.5 border-b border-slate-800/80 text-xs">
              <div className="flex items-center gap-2">
                <span className="font-semibold text-slate-200">
                  {aiOutput.providerUsed}
                </span>
                <span className="text-slate-500 font-mono">({aiOutput.modelUsed})</span>
                <span className="px-1.5 py-0.2 rounded text-[10px] font-bold bg-rose-950 text-rose-300 border border-rose-800 uppercase">
                  Risco: {aiOutput.riskLevel}
                </span>
              </div>
              <div className="font-mono text-indigo-400 text-[11px]">
                {aiOutput.mitreTechnique}
              </div>
            </div>

            {/* Analysis text */}
            <div className="text-xs text-slate-200 whitespace-pre-line leading-relaxed font-sans bg-slate-900/60 p-3.5 rounded-lg border border-slate-800/60">
              {aiOutput.analysis}
            </div>

            {/* Recommended Iptables Command */}
            {aiOutput.validatedCommand && (
              <div className="space-y-1.5">
                <span className="text-[11px] font-semibold text-slate-400 block">
                  Regra Iptables Netfilter Validada pela IA:
                </span>
                <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800 flex items-center justify-between gap-2">
                  <code className="text-xs font-mono text-emerald-400 truncate">
                    {aiOutput.validatedCommand}
                  </code>
                  <div className="flex items-center gap-1.5 shrink-0">
                    <button
                      onClick={() => handleCopyCommand(aiOutput.validatedCommand!)}
                      className="p-1 text-slate-400 hover:text-slate-200 rounded hover:bg-slate-800 transition-colors"
                      title="Copiar comando"
                    >
                      {copiedCmd ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    </button>
                    {onOpenKaliTerminal && (
                      <button
                        onClick={() => onOpenKaliTerminal(aiOutput.validatedCommand!)}
                        className="px-2 py-1 rounded bg-cyan-950 text-cyan-300 border border-cyan-800/80 hover:bg-cyan-900/60 text-[11px] font-semibold flex items-center gap-1 transition-colors"
                      >
                        <Play className="w-3 h-3 fill-cyan-400 text-cyan-400" />
                        <span>Terminal Kali</span>
                      </button>
                    )}
                  </div>
                </div>
              </div>
            )}

            {/* Action checklist */}
            {aiOutput.recommendedActions && aiOutput.recommendedActions.length > 0 && (
              <div className="pt-2">
                <span className="text-[11px] font-semibold text-slate-400 block mb-1.5">
                  Ações Imediatas Sugeridas pelo SOC:
                </span>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-xs">
                  {aiOutput.recommendedActions.map((act, i) => (
                    <div key={i} className="p-2 rounded bg-slate-900 border border-slate-800 text-slate-300 flex items-start gap-2">
                      <span className="w-4 h-4 rounded-full bg-cyan-950 text-cyan-400 border border-cyan-800 text-[10px] flex items-center justify-center shrink-0 font-bold">
                        {i + 1}
                      </span>
                      <span className="text-[11px]">{act}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        ) : (
          <div className="p-8 text-center bg-slate-950/60 rounded-xl border border-slate-800/80 space-y-2">
            <Bot className="w-8 h-8 text-slate-600 mx-auto" />
            <p className="text-sm font-medium text-slate-300">Nenhuma análise gerada nesta sessão</p>
            <p className="text-xs text-slate-500 max-w-md mx-auto">
              Clique no botão acima para submeter a última telemetria do sniffer ao motor <strong className="text-cyan-400">{activeProviderConfig.name}</strong> ({settings.selectedModel}).
            </p>
          </div>
        )}
      </div>

      {/* 5. Safe Key Configuration Guide for Kali Linux */}
      <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 text-xs space-y-2.5">
        <div className="flex items-center gap-2 text-slate-300 font-semibold">
          <Key className="w-4 h-4 text-amber-400" />
          <span>Como Configurar Chaves de API no Kali Linux com Segurança (Sem Expor no Navegador)</span>
        </div>
        <p className="text-slate-400 leading-relaxed text-[11px]">
          Para preservar a segurança da sua rede, chaves secretas de APIs na nuvem nunca devem ser digitadas em campos no navegador. No Kali Linux, configure-as no arquivo de variáveis de ambiente do contêiner em <code className="text-cyan-400 font-mono">/opt/netsentry/.env</code>:
        </p>
        <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 font-mono text-[11px] text-slate-300 space-y-1">
          <div className="text-slate-500"># /opt/netsentry/.env</div>
          <div>GEMINI_API_KEY="AIzaSy..."</div>
          <div>ANTHROPIC_API_KEY="sk-ant-..."</div>
          <div>OPENAI_API_KEY="sk-proj-..."</div>
          <div>OLLAMA_BASE_URL="http://127.0.0.1:11434"</div>
        </div>
      </div>
    </div>
  );
};
