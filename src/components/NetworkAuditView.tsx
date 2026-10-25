import React, { useState, useEffect } from 'react';
import { 
  Network, 
  Server, 
  ShieldAlert, 
  CheckCircle2, 
  AlertTriangle, 
  Terminal, 
  Cpu, 
  Zap, 
  RotateCw, 
  Plus, 
  Trash2, 
  Key, 
  Sparkles, 
  Layers, 
  Wifi, 
  Lock, 
  Check, 
  X, 
  Sliders, 
  Activity, 
  Search,
  ChevronRight,
  Info
} from 'lucide-react';
import { 
  EquipmentProfile, 
  EquipmentCredential, 
  NetworkDiagnosticResult, 
  EquipmentBrand,
  NetworkAuditIssue,
  SeverityLevel,
  NetworkDevice
} from '../types';
import { networkEngine } from '../services/networkEngine';
import { NetworkTopologyVisualizer } from './NetworkTopologyVisualizer';
import { SecureCredentialsForm } from './SecureCredentialsForm';

interface NetworkAuditViewProps {
  devices?: NetworkDevice[];
  onOpenKaliTerminal?: (cmd: string) => void;
  onToast?: (msg: string, type?: 'success' | 'alert') => void;
  onOpenAIForensic?: (type: 'device', device: NetworkDevice) => void;
  onScanSubnet?: (deep?: boolean) => void;
}

export const NetworkAuditView: React.FC<NetworkAuditViewProps> = ({
  devices = [],
  onOpenKaliTerminal,
  onToast,
  onOpenAIForensic,
  onScanSubnet
}) => {
  const [activeAuditTab, setActiveAuditTab] = useState<'topology' | 'credentials' | 'diagnostic' | 'hardware'>('credentials');
  const [isRunningDiag, setIsRunningDiag] = useState(false);
  const [diagResult, setDiagResult] = useState<NetworkDiagnosticResult | null>(null);
  
  // Equipment Catalog & Credentials State
  const [profiles, setProfiles] = useState<EquipmentProfile[]>([]);
  const [credentials, setCredentials] = useState<EquipmentCredential[]>([]);
  const [isLoadingEquip, setIsLoadingEquip] = useState(false);

  // Modal / Form States
  const [showAddProfileModal, setShowAddProfileModal] = useState(false);
  const [showAddCredModal, setShowAddCredModal] = useState(false);
  const [testingCredId, setTestingCredId] = useState<string | null>(null);

  // New Profile Form State
  const [newProfile, setNewProfile] = useState<Partial<EquipmentProfile>>({
    name: '',
    brand: 'cisco',
    model: '',
    expectedIp: '',
    expectedRole: 'core_switch',
    firmwareVersion: '',
    notes: ''
  });

  // New Credential Form State
  const [newCred, setNewCred] = useState<Partial<EquipmentCredential>>({
    profileId: '',
    targetIp: '',
    targetPort: 22,
    protocol: 'ssh',
    username: 'view_auditor',
    password: '',
    snmpCommunity: '',
    isReadOnly: true
  });

  const loadEquipments = async () => {
    setIsLoadingEquip(true);
    try {
      const data = await networkEngine.getEquipmentsData();
      setProfiles(data.profiles || []);
      setCredentials(data.credentials || []);
    } catch {
      // Fallback
    } finally {
      setIsLoadingEquip(false);
    }
  };

  useEffect(() => {
    loadEquipments();
    // Run initial diagnostic check
    handleRunDiagnostic();
  }, []);

  const handleRunDiagnostic = async () => {
    setIsRunningDiag(true);
    try {
      const result = await networkEngine.runNetworkAudit();
      setDiagResult(result);
      if (onToast) {
        onToast(
          result.dhcpServersFound.length > 1
            ? 'Atenção: Detectado mais de 1 Servidor DHCP na rede local!'
            : 'Diagnóstico de rede e auditoria de equipamentos concluído com sucesso!',
          result.dhcpServersFound.length > 1 ? 'alert' : 'success'
        );
      }
    } catch (err: any) {
      if (onToast) onToast(err.message || 'Erro ao executar o diagnóstico de rede.', 'alert');
    } finally {
      setIsRunningDiag(false);
    }
  };

  const handleSaveProfile = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newProfile.name || !newProfile.brand || !newProfile.model) {
      if (onToast) onToast('Preencha os campos obrigatórios do equipamento.', 'alert');
      return;
    }

    try {
      await networkEngine.saveEquipmentProfile(newProfile as EquipmentProfile);
      setShowAddProfileModal(false);
      setNewProfile({
        name: '',
        brand: 'cisco',
        model: '',
        expectedIp: '',
        expectedRole: 'core_switch',
        firmwareVersion: '',
        notes: ''
      });
      loadEquipments();
      if (onToast) onToast('Equipamento cadastrado com sucesso!', 'success');
    } catch (err: any) {
      if (onToast) onToast(err.message || 'Erro ao cadastrar equipamento.', 'alert');
    }
  };

  const handleDeleteProfile = async (id: string) => {
    try {
      await networkEngine.deleteEquipmentProfile(id);
      loadEquipments();
      if (onToast) onToast('Equipamento removido do catálogo.', 'success');
    } catch (err: any) {
      if (onToast) onToast(err.message || 'Erro ao remover equipamento.', 'alert');
    }
  };

  const handleSaveCredential = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newCred.targetIp || !newCred.username || !newCred.protocol) {
      if (onToast) onToast('Preencha o IP, usuário e protocolo.', 'alert');
      return;
    }

    try {
      await networkEngine.saveEquipmentCredential(newCred as EquipmentCredential);
      setShowAddCredModal(false);
      setNewCred({
        profileId: '',
        targetIp: '',
        targetPort: 22,
        protocol: 'ssh',
        username: 'view_auditor',
        password: '',
        snmpCommunity: '',
        isReadOnly: true
      });
      loadEquipments();
      if (onToast) onToast('Credencial com permissão View salva com sucesso!', 'success');
    } catch (err: any) {
      if (onToast) onToast(err.message || 'Erro ao salvar credencial.', 'alert');
    }
  };

  const handleDeleteCredential = async (id: string) => {
    try {
      await networkEngine.deleteEquipmentCredential(id);
      loadEquipments();
      if (onToast) onToast('Credencial removida.', 'success');
    } catch (err: any) {
      if (onToast) onToast(err.message || 'Erro ao remover credencial.', 'alert');
    }
  };

  const handleTestCredential = async (id: string) => {
    setTestingCredId(id);
    try {
      const res = await networkEngine.testEquipmentCredential(id);
      if (res.success) {
        if (onToast) onToast(res.message, 'success');
      } else {
        if (onToast) onToast(res.message, 'alert');
      }
      loadEquipments();
    } catch (err: any) {
      if (onToast) onToast(err.message || 'Erro ao testar credencial.', 'alert');
    } finally {
      setTestingCredId(null);
    }
  };

  const getBrandBadge = (brand: EquipmentBrand) => {
    const brandStyles: Record<EquipmentBrand, { label: string; color: string }> = {
      cisco: { label: 'CISCO', color: 'bg-blue-950 text-blue-300 border-blue-700' },
      mikrotik: { label: 'MIKROTIK', color: 'bg-emerald-950 text-emerald-300 border-emerald-700' },
      ubiquiti: { label: 'UBIQUITI', color: 'bg-cyan-950 text-cyan-300 border-cyan-700' },
      tplink: { label: 'TP-LINK', color: 'bg-teal-950 text-teal-300 border-teal-700' },
      fortinet: { label: 'FORTINET', color: 'bg-rose-950 text-rose-300 border-rose-700' },
      pfsense: { label: 'PFSENSE', color: 'bg-purple-950 text-purple-300 border-purple-700' },
      huawei: { label: 'HUAWEI', color: 'bg-red-950 text-red-300 border-red-700' },
      intelbras: { label: 'INTELBRAS', color: 'bg-green-950 text-green-300 border-green-700' },
      generic: { label: 'GENÉRICO', color: 'bg-slate-800 text-slate-300 border-slate-700' }
    };
    const b = brandStyles[brand] || brandStyles.generic;
    return (
      <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${b.color}`}>
        {b.label}
      </span>
    );
  };

  const getSeverityBadge = (severity: SeverityLevel) => {
    switch (severity) {
      case 'critical':
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-950 text-rose-300 border border-rose-800">CRÍTICO</span>;
      case 'high':
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-950 text-amber-300 border border-amber-800">ALTO</span>;
      case 'medium':
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-yellow-950 text-yellow-300 border border-yellow-800">MÉDIO</span>;
      default:
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono text-slate-300 bg-slate-800 border border-slate-700">BAIXO</span>;
    }
  };

  return (
    <div className="space-y-6">
      {/* 1. Header Banner */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 p-5 rounded-xl bg-slate-900 border border-slate-800 shadow-lg">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <div className="w-8 h-8 rounded-lg bg-cyan-950 border border-cyan-700 flex items-center justify-center text-cyan-400">
              <Network className="w-4 h-4" />
            </div>
            <h1 className="text-lg font-bold text-slate-100 flex items-center gap-2">
              <span>Diagnóstico Profundo de Rede & Equipamentos</span>
              <span className="text-[11px] font-mono text-cyan-400 bg-cyan-950 px-2 py-0.5 rounded border border-cyan-800">
                Auditoria Interna (LAN)
              </span>
            </h1>
          </div>
          <p className="text-xs text-slate-400 max-w-3xl leading-relaxed">
            Identifique múltiplos servidores DHCP competindo (Rogue DHCP), latência e loops de DNS, falhas de roteamento e audite switches, roteadores e firewalls com credenciais seguras de usuário de leitura (view-only), assistido por IA com base na marca e modelo exatos.
          </p>
        </div>

        <button
          onClick={handleRunDiagnostic}
          disabled={isRunningDiag}
          className="flex items-center gap-2 px-5 py-2.5 bg-cyan-400 hover:bg-cyan-300 disabled:opacity-75 text-slate-950 font-bold text-xs rounded-lg transition-all shadow-md shrink-0 self-start lg:self-auto cursor-pointer"
        >
          {isRunningDiag ? (
            <>
              <RotateCw className="w-4 h-4 animate-spin" />
              <span>Diagnosticando Rede...</span>
            </>
          ) : (
            <>
              <Zap className="w-4 h-4 fill-slate-950" />
              <span>Executar Diagnóstico Profundo</span>
            </>
          )}
        </button>
      </div>

      {/* 2. Critical Alert Banner: Rogue DHCP Detection (User Explicit Request) */}
      {diagResult && diagResult.dhcpServersFound.length > 1 && (
        <div className="p-4 rounded-xl bg-gradient-to-r from-rose-950/80 via-slate-900 to-rose-950/80 border border-rose-700/80 shadow-2xl flex flex-col md:flex-row md:items-center justify-between gap-4 animate-pulse">
          <div className="flex items-start gap-3">
            <div className="p-2 rounded-lg bg-rose-950 border border-rose-600 text-rose-400 shrink-0">
              <ShieldAlert className="w-6 h-6" />
            </div>
            <div className="space-y-1">
              <h3 className="text-sm font-bold text-rose-200 flex items-center gap-2">
                <span>ALERTA DE SEGURANÇA: Múltiplos Servidores DHCP Detectados na Rede!</span>
                <span className="text-[10px] font-mono bg-rose-900 text-rose-100 px-2 py-0.5 rounded">
                  {diagResult.dhcpServersFound.length} Servidores Ativos
                </span>
              </h3>
              <p className="text-xs text-rose-300/90 leading-relaxed font-sans">
                Foi detectado mais de 1 servidor DHCP respondendo na mesma rede local. O gateway primário é <strong>192.168.0.1</strong>, porém há outro dispositivo oferecendo endereços IP na LAN, causando conflitos de rota, queda de conexão e risco de ataque Man-in-the-Middle (Rogue DHCP Server).
              </p>
            </div>
          </div>

          {onOpenKaliTerminal && (
            <button
              onClick={() => onOpenKaliTerminal(`sudo nmap -sU -p 67 --script broadcast-dhcp-discover 192.168.0.255`)}
              className="px-4 py-2 bg-rose-600 hover:bg-rose-500 text-white font-bold text-xs rounded-lg transition-colors shrink-0 flex items-center gap-1.5 shadow-md self-start md:self-auto"
            >
              <Terminal className="w-3.5 h-3.5" />
              <span>Localizar Porta no Kali</span>
            </button>
          )}
        </div>
      )}

      {/* 3. Diagnostic Health Overview Cards */}
      {diagResult && (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {/* DHCP Status */}
          <div className={`p-4 rounded-xl border ${diagResult.dhcpServersFound.length > 1 ? 'bg-rose-950/40 border-rose-800' : 'bg-slate-900 border-slate-800'} space-y-1.5`}>
            <div className="flex items-center justify-between">
              <span className="text-[11px] uppercase tracking-wider font-semibold text-slate-400">Servidores DHCP</span>
              {diagResult.dhcpServersFound.length > 1 ? (
                <span className="text-[10px] font-mono font-bold bg-rose-950 text-rose-300 border border-rose-700 px-1.5 py-0.2 rounded">CONFLITO</span>
              ) : (
                <span className="text-[10px] font-mono font-bold bg-emerald-950 text-emerald-300 border border-emerald-700 px-1.5 py-0.2 rounded">NORMAL</span>
              )}
            </div>
            <div className="text-2xl font-extrabold font-mono text-slate-100">
              {diagResult.dhcpServersFound.length} <span className="text-xs font-normal text-slate-400">detectado(s)</span>
            </div>
            <div className="text-[11px] text-slate-400 truncate">
              Gateway: <strong className="text-slate-200">192.168.0.1</strong> {diagResult.dhcpServersFound.length > 1 && <span className="text-rose-400">(+1 intruso)</span>}
            </div>
          </div>

          {/* DNS Health */}
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-1.5">
            <div className="flex items-center justify-between">
              <span className="text-[11px] uppercase tracking-wider font-semibold text-slate-400">Saúde do DNS</span>
              <span className="text-[10px] font-mono font-bold bg-emerald-950 text-emerald-300 border border-emerald-700 px-1.5 py-0.2 rounded">ESTÁVEL</span>
            </div>
            <div className="text-2xl font-extrabold font-mono text-slate-100">
              {diagResult.dnsServersTested[0]?.latencyMs || 12} <span className="text-xs font-normal text-slate-400">ms média</span>
            </div>
            <div className="text-[11px] text-slate-400 truncate">
              {diagResult.dnsServersTested.length} servidores testados sem loops
            </div>
          </div>

          {/* Routing Health */}
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-1.5">
            <div className="flex items-center justify-between">
              <span className="text-[11px] uppercase tracking-wider font-semibold text-slate-400">Roteamento & Gateway</span>
              <span className="text-[10px] font-mono font-bold bg-cyan-950 text-cyan-300 border border-cyan-700 px-1.5 py-0.2 rounded">ATIVO</span>
            </div>
            <div className="text-2xl font-extrabold font-mono text-slate-100">
              {diagResult.routingHealth.defaultGateway}
            </div>
            <div className="text-[11px] text-slate-400 truncate">
              Hop 1 responsivo · Perda: {diagResult.routingHealth.packetLossPercent}%
            </div>
          </div>

          {/* Equipments Audited */}
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-1.5">
            <div className="flex items-center justify-between">
              <span className="text-[11px] uppercase tracking-wider font-semibold text-slate-400">Equipamentos Auditados</span>
              <span className="text-[10px] font-mono font-bold bg-indigo-950 text-indigo-300 border border-indigo-700 px-1.5 py-0.2 rounded">PERFIL VIEW</span>
            </div>
            <div className="text-2xl font-extrabold font-mono text-slate-100">
              {profiles.length} <span className="text-xs font-normal text-slate-400">cadastrados</span>
            </div>
            <div className="text-[11px] text-slate-400 truncate">
              {credentials.length} credenciais view ativas
            </div>
          </div>
        </div>
      )}

      {/* 4. Sub-Navigation Tabs */}
      <div className="flex items-center gap-2 border-b border-slate-800 pb-2 overflow-x-auto">
        <button
          onClick={() => setActiveAuditTab('topology')}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-bold transition-all cursor-pointer ${
            activeAuditTab === 'topology'
              ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-700/80 shadow-md'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
          }`}
        >
          <Network className="w-4 h-4 text-cyan-400" />
          <span>Topologia de Rede D3.js</span>
          <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-cyan-950 text-cyan-300 border border-cyan-800 font-bold">
            Mapeamento Nmap
          </span>
        </button>

        <button
          onClick={() => setActiveAuditTab('credentials')}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-bold transition-all cursor-pointer ${
            activeAuditTab === 'credentials'
              ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-700/80 shadow-md'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
          }`}
        >
          <Key className="w-4 h-4 text-cyan-400" />
          <span>Credenciais Seguras & SNMP</span>
          <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-indigo-950 text-indigo-300 border border-indigo-800 font-bold">
            SNMPv3 / View
          </span>
        </button>

        <button
          onClick={() => setActiveAuditTab('diagnostic')}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-bold transition-all cursor-pointer ${
            activeAuditTab === 'diagnostic'
              ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-700/80 shadow-md'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
          }`}
        >
          <Activity className="w-4 h-4 text-cyan-400" />
          <span>Diagnóstico de Infra & DHCP</span>
          {diagResult && diagResult.issues.length > 0 && (
            <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-amber-950 text-amber-300 border border-amber-800 font-bold">
              {diagResult.issues.length}
            </span>
          )}
        </button>

        <button
          onClick={() => setActiveAuditTab('hardware')}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-bold transition-all cursor-pointer ${
            activeAuditTab === 'hardware'
              ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-700/80 shadow-md'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
          }`}
        >
          <Layers className="w-4 h-4 text-cyan-400" />
          <span>Catálogo de Hardware & View</span>
          <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-slate-800 text-slate-300 font-bold">
            {profiles.length}
          </span>
        </button>
      </div>

      {/* Tab 1: D3.js Network Topology Visualizer */}
      {activeAuditTab === 'topology' && (
        <NetworkTopologyVisualizer
          devices={devices}
          profiles={profiles}
          diagResult={diagResult}
          onOpenKaliTerminal={onOpenKaliTerminal}
          onOpenAIForensic={onOpenAIForensic}
          onScanSubnet={onScanSubnet}
          onToast={onToast}
        />
      )}

      {/* Tab 2: Secure Credentials & SNMP Diagnostic Form */}
      {activeAuditTab === 'credentials' && (
        <SecureCredentialsForm
          profiles={profiles}
          credentials={credentials}
          onRefresh={loadEquipments}
          onOpenKaliTerminal={onOpenKaliTerminal}
          onToast={onToast}
        />
      )}

      {/* Tab 2: AI Deep Forensic Diagnostic by Brand & Model */}
      {activeAuditTab === 'diagnostic' && (
        <div className="space-y-6">
          {diagResult?.aiDiagnosticSummary && (
            <div className="p-5 rounded-xl bg-gradient-to-r from-slate-900 via-indigo-950/40 to-slate-900 border border-indigo-800/60 shadow-lg space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <div className="p-1.5 rounded-md bg-indigo-950 border border-indigo-700 text-cyan-400">
                <Sparkles className="w-4 h-4" />
              </div>
              <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                <span>Diagnóstico com IA: Análise de Topologia & Hardening por Marca/Modelo</span>
                <span className="text-[10px] font-mono bg-indigo-950 text-indigo-300 px-2 py-0.5 rounded border border-indigo-800">
                  Cisco · MikroTik · Ubiquiti · Fortinet
                </span>
              </h3>
            </div>
          </div>

          <p className="text-xs text-slate-300 leading-relaxed font-sans whitespace-pre-line">
            {diagResult.aiDiagnosticSummary}
          </p>

          {diagResult.aiActionPlan && diagResult.aiActionPlan.length > 0 && (
            <div className="pt-3 border-t border-indigo-900/40">
              <span className="text-[11px] font-semibold uppercase tracking-wider text-indigo-300 block mb-2">
                Recomendações Técnicas para os Equipamentos da Rede
              </span>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs">
                {diagResult.aiActionPlan.map((step, idx) => (
                  <div key={idx} className="flex items-start gap-2 p-2.5 rounded-lg bg-slate-950/70 border border-slate-800/80">
                    <span className="text-cyan-400 font-mono font-bold shrink-0">{idx + 1}.</span>
                    <span className="text-slate-300 font-sans">{step}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* 5. Identified Issues & Recommendations List */}
      {diagResult && diagResult.issues.length > 0 && (
        <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
          <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
            <span>Problemas e Apontamentos da Rede Interna</span>
            <span className="text-xs font-mono text-cyan-400 bg-cyan-950 px-2 py-0.5 rounded border border-cyan-800">
              {diagResult.issues.length}
            </span>
          </h3>

          <div className="space-y-3">
            {diagResult.issues.map((issue) => (
              <div
                key={issue.id}
                className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2 hover:border-slate-700 transition-colors"
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div className="flex items-center gap-2 flex-wrap">
                    {getSeverityBadge(issue.severity)}
                    <h4 className="text-sm font-semibold text-slate-200">{issue.title}</h4>
                    <span className="text-[11px] font-mono text-slate-400 bg-slate-900 px-2 py-0.5 rounded border border-slate-800">
                      Alvo: {issue.affectedTarget}
                    </span>
                  </div>

                  {issue.kaliCommand && onOpenKaliTerminal && (
                    <button
                      onClick={() => onOpenKaliTerminal(issue.kaliCommand || '')}
                      className="flex items-center gap-1.5 px-3 py-1 bg-cyan-950 hover:bg-cyan-900 text-cyan-300 border border-cyan-800/80 rounded text-xs font-mono transition-colors shrink-0 self-start sm:self-auto"
                    >
                      <Terminal className="w-3.5 h-3.5" />
                      <span>Mitigar no Kali</span>
                    </button>
                  )}
                </div>

                <p className="text-xs text-slate-400 leading-relaxed font-sans">
                  {issue.description}
                </p>

                <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800/80 text-xs text-slate-300 flex items-center gap-2">
                  <span className="text-cyan-400 font-bold shrink-0 font-mono">Correção:</span>
                  <span className="font-sans">{issue.recommendation}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
        </div>
      )}

      {/* Tab 3: Equipment Brand & Model Hardware Catalog & View Credentials Manager */}
      {activeAuditTab === 'hardware' && (
        <div className="grid grid-cols-1 xl:grid-cols-12 gap-6">
        {/* Left Column (7 cols): Hardware Catalog with Brands and Models */}
        <div className="xl:col-span-7 p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-4">
          <div className="flex items-center justify-between">
            <div className="space-y-0.5">
              <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                <Layers className="w-4 h-4 text-cyan-400" />
                <span>Catálogo de Equipamentos da Rede (Marca & Modelo)</span>
              </h3>
              <p className="text-xs text-slate-400">
                Cadastre os modelos dos switches, roteadores e firewalls para que a IA aplique regras de auditoria específicas do fabricante.
              </p>
            </div>

            <button
              onClick={() => setShowAddProfileModal(true)}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-cyan-400 hover:bg-cyan-300 text-slate-950 font-bold text-xs rounded-lg transition-colors shrink-0 shadow-sm"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>Novo Equipamento</span>
            </button>
          </div>

          <div className="space-y-2.5">
            {profiles.length === 0 ? (
              <div className="p-6 text-center text-slate-500 text-xs">
                Nenhum equipamento cadastrado ainda. Clique em "Novo Equipamento" acima.
              </div>
            ) : (
              profiles.map((prof) => (
                <div
                  key={prof.id}
                  className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 hover:border-slate-700 transition-all flex flex-col sm:flex-row sm:items-center justify-between gap-3"
                >
                  <div className="space-y-1">
                    <div className="flex items-center gap-2 flex-wrap">
                      {getBrandBadge(prof.brand)}
                      <strong className="text-xs text-slate-200">{prof.name}</strong>
                      <span className="text-[11px] font-mono text-cyan-300 bg-cyan-950/60 px-1.5 py-0.2 rounded border border-cyan-800/60">
                        {prof.model}
                      </span>
                    </div>
                    <div className="text-[11px] text-slate-400 font-mono">
                      IP Previsto: <strong className="text-slate-200">{prof.expectedIp || 'DHCP'}</strong> · Papel: <strong className="capitalize text-slate-300">{prof.expectedRole}</strong> · Firmware: {prof.firmwareVersion || 'Padrão'}
                    </div>
                  </div>

                  <div className="flex items-center gap-2 shrink-0">
                    {onOpenKaliTerminal && prof.expectedIp && (
                      <button
                        onClick={() => onOpenKaliTerminal(`sudo nmap -sV -O ${prof.expectedIp}`)}
                        className="p-1.5 text-slate-400 hover:text-cyan-300 rounded hover:bg-slate-800 transition-colors"
                        title="Escanear portas deste equipamento no Kali"
                      >
                        <Terminal className="w-3.5 h-3.5" />
                      </button>
                    )}
                    <button
                      onClick={() => handleDeleteProfile(prof.id)}
                      className="p-1.5 text-slate-500 hover:text-rose-400 rounded hover:bg-slate-800 transition-colors"
                      title="Excluir equipamento"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Right Column (5 cols): Secure View Credentials Manager */}
        <div className="xl:col-span-5 p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-4">
          <div className="flex items-center justify-between">
            <div className="space-y-0.5">
              <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                <Key className="w-4 h-4 text-cyan-400" />
                <span>Credenciais Seguras (Usuário View / Leitura)</span>
              </h3>
              <p className="text-xs text-slate-400">
                Acesso restrito de auditoria (read-only) para diagnóstico profundo.
              </p>
            </div>

            <button
              onClick={() => setShowAddCredModal(true)}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 font-semibold text-xs rounded-lg transition-colors shrink-0 border border-slate-700"
            >
              <Plus className="w-3.5 h-3.5 text-cyan-400" />
              <span>Adicionar View</span>
            </button>
          </div>

          <div className="space-y-2.5">
            {credentials.length === 0 ? (
              <div className="p-6 text-center text-slate-500 text-xs">
                Nenhuma credencial de leitura cadastrada.
              </div>
            ) : (
              credentials.map((cred) => (
                <div
                  key={cred.id}
                  className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 hover:border-slate-700 transition-all space-y-2"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-[10px] font-mono font-bold uppercase bg-slate-800 text-slate-300 px-1.5 py-0.5 rounded border border-slate-700">
                        {cred.protocol.toUpperCase()}
                      </span>
                      <span className="text-xs font-mono font-bold text-slate-200">{cred.targetIp}:{cred.targetPort}</span>
                      <span className="text-[10px] font-mono bg-emerald-950 text-emerald-300 border border-emerald-800 px-1.5 py-0.2 rounded">
                        VIEW-ONLY
                      </span>
                    </div>

                    <div className="flex items-center gap-1.5">
                      <button
                        onClick={() => handleTestCredential(cred.id)}
                        disabled={testingCredId === cred.id}
                        className="px-2 py-1 bg-cyan-950 hover:bg-cyan-900 border border-cyan-800 text-cyan-300 text-[11px] font-mono rounded transition-colors flex items-center gap-1 cursor-pointer"
                        title="Verificar conectividade com a porta do equipamento"
                      >
                        {testingCredId === cred.id ? (
                          <RotateCw className="w-3 h-3 animate-spin" />
                        ) : (
                          <Zap className="w-3 h-3" />
                        )}
                        <span>Testar</span>
                      </button>

                      <button
                        onClick={() => handleDeleteCredential(cred.id)}
                        className="p-1 text-slate-500 hover:text-rose-400 rounded hover:bg-slate-800 transition-colors"
                        title="Excluir credencial"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </div>

                  <div className="flex items-center justify-between text-[11px] text-slate-400 font-mono">
                    <span>Usuário: <strong className="text-slate-200">{cred.username}</strong></span>
                    <span className={cred.authStatus === 'valid' ? 'text-emerald-400 font-semibold' : 'text-slate-500'}>
                      {cred.authStatus === 'valid' ? '● Acesso Validado' : cred.authStatus === 'failed' ? '● Inacessível' : '● Não testado'}
                    </span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
      )}

      {/* Modal: Novo Equipamento */}
      {showAddProfileModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-fadeIn">
          <div className="relative w-full max-w-lg bg-slate-900 border border-slate-800 rounded-xl shadow-2xl p-6 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                <Layers className="w-4 h-4 text-cyan-400" />
                <span>Cadastrar Equipamento de Rede</span>
              </h3>
              <button
                onClick={() => setShowAddProfileModal(false)}
                className="text-slate-400 hover:text-slate-200 p-1"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleSaveProfile} className="space-y-3.5 text-xs">
              <div>
                <label className="text-slate-400 block mb-1">Nome de Identificação (ex: Switch Core Rack 1)</label>
                <input
                  type="text"
                  required
                  value={newProfile.name}
                  onChange={(e) => setNewProfile({ ...newProfile, name: e.target.value })}
                  placeholder="Nome amigável na rede..."
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-slate-100 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-slate-400 block mb-1">Fabricante (Marca)</label>
                  <select
                    value={newProfile.brand}
                    onChange={(e) => setNewProfile({ ...newProfile, brand: e.target.value as EquipmentBrand })}
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-slate-100 focus:outline-none focus:border-cyan-500 font-mono"
                  >
                    <option value="cisco">Cisco</option>
                    <option value="mikrotik">MikroTik</option>
                    <option value="ubiquiti">Ubiquiti</option>
                    <option value="tplink">TP-Link</option>
                    <option value="fortinet">Fortinet</option>
                    <option value="pfsense">pfSense</option>
                    <option value="huawei">Huawei</option>
                    <option value="intelbras">Intelbras</option>
                    <option value="generic">Outro / Genérico</option>
                  </select>
                </div>

                <div>
                  <label className="text-slate-400 block mb-1">Modelo Exato (ex: Catalyst 2960)</label>
                  <input
                    type="text"
                    required
                    value={newProfile.model}
                    onChange={(e) => setNewProfile({ ...newProfile, model: e.target.value })}
                    placeholder="ex: RB3011, USW-24-PoE..."
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-slate-100 focus:outline-none focus:border-cyan-500 font-mono"
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-slate-400 block mb-1">Endereço IP Previsto (Gerência)</label>
                  <input
                    type="text"
                    value={newProfile.expectedIp}
                    onChange={(e) => setNewProfile({ ...newProfile, expectedIp: e.target.value })}
                    placeholder="192.168.0.X..."
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-slate-100 focus:outline-none focus:border-cyan-500 font-mono"
                  />
                </div>

                <div>
                  <label className="text-slate-400 block mb-1">Função na Topologia</label>
                  <select
                    value={newProfile.expectedRole}
                    onChange={(e) => setNewProfile({ ...newProfile, expectedRole: e.target.value as any })}
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-slate-100 focus:outline-none focus:border-cyan-500 font-mono"
                  >
                    <option value="gateway">Roteador / Gateway</option>
                    <option value="core_switch">Switch Core / Distribuição</option>
                    <option value="access_switch">Switch de Acesso</option>
                    <option value="firewall">Firewall / Borda</option>
                    <option value="access_point">Access Point Wi-Fi</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="text-slate-400 block mb-1">Versão de Firmware / SO (Opcional)</label>
                <input
                  type="text"
                  value={newProfile.firmwareVersion}
                  onChange={(e) => setNewProfile({ ...newProfile, firmwareVersion: e.target.value })}
                  placeholder="ex: IOS 15.2, RouterOS 7.14..."
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-slate-100 focus:outline-none focus:border-cyan-500 font-mono"
                />
              </div>

              <div className="flex items-center justify-end gap-2 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowAddProfileModal(false)}
                  className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 font-semibold rounded-lg"
                >
                  Cancelar
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 bg-cyan-400 hover:bg-cyan-300 text-slate-950 font-bold rounded-lg shadow-sm"
                >
                  Salvar Equipamento
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Modal: Nova Credencial View */}
      {showAddCredModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-fadeIn">
          <div className="relative w-full max-w-lg bg-slate-900 border border-slate-800 rounded-xl shadow-2xl p-6 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                <Key className="w-4 h-4 text-cyan-400" />
                <span>Cadastrar Credencial de Leitura (View-Only)</span>
              </h3>
              <button
                onClick={() => setShowAddCredModal(false)}
                className="text-slate-400 hover:text-slate-200 p-1"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="p-2.5 rounded-lg bg-cyan-950/50 border border-cyan-800/60 text-[11px] text-cyan-300 flex items-center gap-2">
              <Info className="w-4 h-4 shrink-0 text-cyan-400" />
              <span>Por segurança, use estritamente usuários com perfil de consulta/leitura sem privilégios de gravação ou alteração de configurações.</span>
            </div>

            <form onSubmit={handleSaveCredential} className="space-y-3.5 text-xs">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-slate-400 block mb-1">IP do Equipamento</label>
                  <input
                    type="text"
                    required
                    value={newCred.targetIp}
                    onChange={(e) => setNewCred({ ...newCred, targetIp: e.target.value })}
                    placeholder="192.168.0.1..."
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-slate-100 focus:outline-none focus:border-cyan-500 font-mono"
                  />
                </div>

                <div>
                  <label className="text-slate-400 block mb-1">Protocolo</label>
                  <select
                    value={newCred.protocol}
                    onChange={(e) => {
                      const proto = e.target.value as any;
                      setNewCred({ 
                        ...newCred, 
                        protocol: proto,
                        targetPort: proto === 'ssh' ? 22 : proto === 'snmp_v2c' ? 161 : proto === 'telnet' ? 23 : 443
                      });
                    }}
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-slate-100 focus:outline-none focus:border-cyan-500 font-mono"
                  >
                    <option value="ssh">SSH (Porta 22 - Recomendado)</option>
                    <option value="snmp_v2c">SNMP v2c (Porta 161 UDP)</option>
                    <option value="snmp_v3">SNMP v3 (Porta 161 Seguro)</option>
                    <option value="https_api">HTTPS Web API (Porta 443)</option>
                    <option value="telnet">Telnet (Porta 23 - Inseguro)</option>
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-slate-400 block mb-1">Porta de Conexão</label>
                  <input
                    type="number"
                    value={newCred.targetPort}
                    onChange={(e) => setNewCred({ ...newCred, targetPort: Number(e.target.value) })}
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-slate-100 focus:outline-none focus:border-cyan-500 font-mono"
                  />
                </div>

                <div>
                  <label className="text-slate-400 block mb-1">Usuário View</label>
                  <input
                    type="text"
                    required
                    value={newCred.username}
                    onChange={(e) => setNewCred({ ...newCred, username: e.target.value })}
                    placeholder="view_auditor, readonly..."
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-slate-100 focus:outline-none focus:border-cyan-500 font-mono"
                  />
                </div>
              </div>

              {newCred.protocol === 'snmp_v2c' ? (
                <div>
                  <label className="text-slate-400 block mb-1">Comunidade SNMP de Leitura (Community)</label>
                  <input
                    type="text"
                    value={newCred.snmpCommunity}
                    onChange={(e) => setNewCred({ ...newCred, snmpCommunity: e.target.value })}
                    placeholder="public, snmp_read..."
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-slate-100 focus:outline-none focus:border-cyan-500 font-mono"
                  />
                </div>
              ) : (
                <div>
                  <label className="text-slate-400 block mb-1">Senha do Usuário View</label>
                  <input
                    type="password"
                    value={newCred.password}
                    onChange={(e) => setNewCred({ ...newCred, password: e.target.value })}
                    placeholder="Senha de leitura..."
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-slate-100 focus:outline-none focus:border-cyan-500 font-mono"
                  />
                </div>
              )}

              <div className="flex items-center justify-end gap-2 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowAddCredModal(false)}
                  className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 font-semibold rounded-lg"
                >
                  Cancelar
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 bg-cyan-400 hover:bg-cyan-300 text-slate-950 font-bold rounded-lg shadow-sm"
                >
                  Salvar Credencial View
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
