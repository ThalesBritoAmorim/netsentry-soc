import React, { useState, useMemo } from 'react';
import { 
  Key, 
  ShieldCheck, 
  Terminal, 
  Activity, 
  Cpu, 
  Server, 
  HardDrive, 
  Eye, 
  EyeOff, 
  Check, 
  Copy, 
  RotateCw, 
  Plus, 
  Trash2, 
  Lock, 
  Zap, 
  Layers, 
  Info,
  CheckCircle2,
  AlertTriangle,
  ChevronDown,
  Sparkles
} from 'lucide-react';
import { 
  EquipmentProfile, 
  EquipmentCredential 
} from '../types';
import { networkEngine } from '../services/networkEngine';

interface SecureCredentialsFormProps {
  profiles: EquipmentProfile[];
  credentials: EquipmentCredential[];
  onRefresh: () => void;
  onOpenKaliTerminal?: (cmd: string) => void;
  onToast?: (msg: string, type?: 'success' | 'alert') => void;
}

export const SecureCredentialsForm: React.FC<SecureCredentialsFormProps> = ({
  profiles,
  credentials,
  onRefresh,
  onOpenKaliTerminal,
  onToast
}) => {
  // Form State
  const [targetIp, setTargetIp] = useState('');
  const [profileId, setProfileId] = useState('');
  const [protocol, setProtocol] = useState<'snmp_v3' | 'snmp_v2c' | 'ssh'>('snmp_v3');
  const [targetPort, setTargetPort] = useState<number>(161);
  const [username, setUsername] = useState('snmp_view_auditor');
  const [password, setPassword] = useState('');
  const [snmpCommunity, setSnmpCommunity] = useState('public_ro');
  
  // SNMPv3 Auth & Priv fields
  const [snmpSecLevel, setSnmpSecLevel] = useState<'authPriv' | 'authNoPriv' | 'noAuthNoPriv'>('authPriv');
  const [snmpAuthProtocol, setSnmpAuthProtocol] = useState<'SHA' | 'SHA-256' | 'MD5'>('SHA');
  const [snmpAuthPassphrase, setSnmpAuthPassphrase] = useState('AuthPass2026!');
  const [snmpPrivProtocol, setSnmpPrivProtocol] = useState<'AES' | 'AES-256' | 'DES'>('AES');
  const [snmpPrivPassphrase, setSnmpPrivPassphrase] = useState('PrivEncryptKey2026!');
  const [snmpContext, setSnmpContext] = useState('');
  const [notes, setNotes] = useState('Auditoria de chassi, interfaces e modelo de hardware');

  // UI helpers
  const [showSecrets, setShowSecrets] = useState(false);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [isTestingId, setIsTestingId] = useState<string | null>(null);
  const [isQueryingId, setIsQueryingId] = useState<string | null>(null);
  const [isSaving, setIsSaving] = useState(false);

  // Link profile selection to form
  const handleSelectProfile = (pId: string) => {
    setProfileId(pId);
    if (!pId) return;
    const prof = profiles.find(p => p.id === pId);
    if (prof && prof.expectedIp) {
      setTargetIp(prof.expectedIp);
    }
  };

  // Switch protocol port default
  const handleProtocolChange = (prot: 'snmp_v3' | 'snmp_v2c' | 'ssh') => {
    setProtocol(prot);
    if (prot === 'ssh') {
      setTargetPort(22);
    } else {
      setTargetPort(161);
    }
  };

  // Generate live Nmap SNMP / diagnostic script command
  const generatedNmapCommand = useMemo(() => {
    const ip = targetIp.trim() || '192.168.0.2';
    const port = targetPort || (protocol === 'ssh' ? 22 : 161);

    if (protocol === 'snmp_v3') {
      const user = username.trim() || 'view_auditor';
      if (snmpSecLevel === 'authPriv') {
        const authKey = showSecrets ? (snmpAuthPassphrase || '••••••') : '••••••••';
        const privKey = showSecrets ? (snmpPrivPassphrase || '••••••') : '••••••••';
        return `nmap -sU -p ${port} --script snmp-info,snmp-interfaces,snmp-sysdescr --script-args snmpversion=3,snmpusername=${user},snmpauth=${snmpAuthProtocol},snmpauthkey=${authKey},snmppriv=${snmpPrivProtocol},snmpprivkey=${privKey} ${ip}`;
      } else if (snmpSecLevel === 'authNoPriv') {
        const authKey = showSecrets ? (snmpAuthPassphrase || '••••••') : '••••••••';
        return `nmap -sU -p ${port} --script snmp-info,snmp-interfaces,snmp-sysdescr --script-args snmpversion=3,snmpusername=${user},snmpauth=${snmpAuthProtocol},snmpauthkey=${authKey} ${ip}`;
      } else {
        return `nmap -sU -p ${port} --script snmp-info,snmp-interfaces,snmp-sysdescr --script-args snmpversion=3,snmpusername=${user} ${ip}`;
      }
    } else if (protocol === 'snmp_v2c') {
      const comm = showSecrets ? (snmpCommunity || 'public') : (snmpCommunity ? '••••••••' : 'public');
      return `nmap -sU -p ${port} --script snmp-info,snmp-interfaces,snmp-sysdescr --script-args snmpcommunity=${comm} ${ip}`;
    } else {
      return `nmap -p ${port} --script ssh2-enum-algos,ssh-hostkey ${ip}`;
    }
  }, [targetIp, targetPort, protocol, username, snmpSecLevel, snmpAuthProtocol, snmpAuthPassphrase, snmpPrivProtocol, snmpPrivPassphrase, snmpCommunity, showSecrets]);

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
    if (onToast) onToast('Comando copiado para a área de transferência!', 'success');
  };

  // Submit / Save Credential
  const handleSaveCredential = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!targetIp.trim() || !username.trim()) {
      if (onToast) onToast('Informe o IP do host alvo e o nome de usuário view.', 'alert');
      return;
    }

    setIsSaving(true);
    try {
      const prof = profiles.find(p => p.id === profileId);
      const newCred: EquipmentCredential = {
        id: `cred-${Date.now()}`,
        profileId: profileId || undefined,
        profileName: prof?.name || undefined,
        targetIp: targetIp.trim(),
        targetPort: Number(targetPort) || (protocol === 'ssh' ? 22 : 161),
        protocol,
        username: username.trim(),
        password: password || undefined,
        snmpCommunity: protocol === 'snmp_v2c' ? snmpCommunity : undefined,
        snmpSecLevel: protocol === 'snmp_v3' ? snmpSecLevel : undefined,
        snmpAuthProtocol: protocol === 'snmp_v3' ? snmpAuthProtocol : undefined,
        snmpAuthPassphrase: protocol === 'snmp_v3' ? snmpAuthPassphrase : undefined,
        snmpPrivProtocol: protocol === 'snmp_v3' ? snmpPrivProtocol : undefined,
        snmpPrivPassphrase: protocol === 'snmp_v3' ? snmpPrivPassphrase : undefined,
        snmpContext: snmpContext.trim() || undefined,
        isReadOnly: true,
        authStatus: 'untested',
        notes: notes.trim() || undefined
      };

      await networkEngine.saveEquipmentCredential(newCred);
      onRefresh();
      if (onToast) onToast('Credencial segura de leitura (View-Only / SNMP) salva com sucesso!', 'success');
      
      // Reset sensitive fields
      setPassword('');
    } catch (err: any) {
      if (onToast) onToast(err.message || 'Erro ao salvar credencial.', 'alert');
    } finally {
      setIsSaving(false);
    }
  };

  // Test Connectivity
  const handleTestCred = async (id: string) => {
    setIsTestingId(id);
    try {
      const res = await networkEngine.testEquipmentCredential(id);
      if (res.success) {
        if (onToast) onToast(res.message, 'success');
      } else {
        if (onToast) onToast(res.message, 'alert');
      }
      onRefresh();
    } catch (err: any) {
      if (onToast) onToast(err.message || 'Falha ao testar credencial.', 'alert');
    } finally {
      setIsTestingId(null);
    }
  };

  // Run SNMP Hardware Query (Nmap snmp-sysdescr & snmp-interfaces)
  const handleRunSnmpQuery = async (id: string) => {
    setIsQueryingId(id);
    try {
      const res = await networkEngine.runSnmpHardwareQuery(id);
      if (res.success) {
        if (onToast) onToast('Consulta SNMP concluída! Inventário de hardware e interfaces atualizado.', 'success');
      } else {
        if (onToast) onToast(res.message || 'Erro na consulta SNMP.', 'alert');
      }
      onRefresh();
    } catch (err: any) {
      if (onToast) onToast(err.message || 'Erro ao consultar via SNMP.', 'alert');
    } finally {
      setIsQueryingId(null);
    }
  };

  // Delete Credential
  const handleDeleteCred = async (id: string) => {
    try {
      await networkEngine.deleteEquipmentCredential(id);
      onRefresh();
      if (onToast) onToast('Credencial removida com segurança.', 'success');
    } catch (err: any) {
      if (onToast) onToast(err.message || 'Erro ao remover credencial.', 'alert');
    }
  };

  return (
    <div className="space-y-6">
      {/* 1. Header Information Banner */}
      <div className="p-5 rounded-xl bg-gradient-to-r from-slate-900 via-indigo-950/40 to-slate-900 border border-indigo-800/60 shadow-lg space-y-2">
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-indigo-950 border border-indigo-700 flex items-center justify-center text-cyan-400 shrink-0">
            <Key className="w-4 h-4" />
          </div>
          <div>
            <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2">
              <span>Cofre de Credenciais Seguras (SNMPv3 / View-Only)</span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-indigo-950 text-indigo-300 border border-indigo-800 font-bold">
                Hardware Inventory Engine
              </span>
            </h2>
            <p className="text-xs text-slate-400">
              Armazene credenciais estritas de leitura (View-Only) para que o Nmap e scripts de diagnóstico executem consultas SNMP autenticadas (sysDescr, chassi, serial, portas ativas e MIBs) sem expor privilégios de escrita.
            </p>
          </div>
        </div>
      </div>

      {/* 2. Main Layout: Form (Left) & Stored Vault (Right) */}
      <div className="grid grid-cols-1 xl:grid-cols-12 gap-6">
        
        {/* Left Form: Add / Configure Secure Credential (7 cols) */}
        <div className="xl:col-span-7 p-5 rounded-xl bg-slate-900 border border-slate-800 shadow-xl space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div className="flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-cyan-400" />
              <h3 className="text-sm font-bold text-slate-100">Cadastrar Credencial de Diagnóstico de Hardware</h3>
            </div>
            <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800 font-bold">
              ● Read-Only Enforced
            </span>
          </div>

          <form onSubmit={handleSaveCredential} className="space-y-4 text-xs">
            {/* Target & Linked Profile */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div>
                <label className="text-slate-300 font-semibold block mb-1">
                  Vincular a Equipamento Cadastrado (Opcional)
                </label>
                <select
                  value={profileId}
                  onChange={(e) => handleSelectProfile(e.target.value)}
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
                >
                  <option value="">-- Inserir IP Manualmente --</option>
                  {profiles.map(p => (
                    <option key={p.id} value={p.id}>
                      {p.name} ({p.brand.toUpperCase()} {p.model}) - {p.expectedIp || 'IP Dinâmico'}
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="text-slate-300 font-semibold block mb-1">
                  Endereço IP do Dispositivo Alvo *
                </label>
                <input
                  type="text"
                  required
                  value={targetIp}
                  onChange={(e) => setTargetIp(e.target.value)}
                  placeholder="ex: 192.168.0.2, 192.168.0.1..."
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-slate-100 focus:outline-none focus:border-cyan-500 font-mono"
                />
              </div>
            </div>

            {/* Protocol Selector */}
            <div>
              <label className="text-slate-300 font-semibold block mb-1.5">
                Protocolo de Coleta de Hardware *
              </label>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
                <button
                  type="button"
                  onClick={() => handleProtocolChange('snmp_v3')}
                  className={`p-2.5 rounded-lg border text-left transition-all cursor-pointer ${
                    protocol === 'snmp_v3'
                      ? 'bg-cyan-950/80 border-cyan-500 text-cyan-200'
                      : 'bg-slate-950 border-slate-800 text-slate-400 hover:border-slate-700'
                  }`}
                >
                  <strong className="block text-xs font-bold text-slate-100">SNMPv3 (authPriv)</strong>
                  <span className="text-[10px] text-slate-400 block mt-0.5">Autenticado & Criptografado (Padrão SOC)</span>
                </button>

                <button
                  type="button"
                  onClick={() => handleProtocolChange('snmp_v2c')}
                  className={`p-2.5 rounded-lg border text-left transition-all cursor-pointer ${
                    protocol === 'snmp_v2c'
                      ? 'bg-cyan-950/80 border-cyan-500 text-cyan-200'
                      : 'bg-slate-950 border-slate-800 text-slate-400 hover:border-slate-700'
                  }`}
                >
                  <strong className="block text-xs font-bold text-slate-100">SNMPv2c (Comunidade)</strong>
                  <span className="text-[10px] text-slate-400 block mt-0.5">Community String somente leitura</span>
                </button>

                <button
                  type="button"
                  onClick={() => handleProtocolChange('ssh')}
                  className={`p-2.5 rounded-lg border text-left transition-all cursor-pointer ${
                    protocol === 'ssh'
                      ? 'bg-cyan-950/80 border-cyan-500 text-cyan-200'
                      : 'bg-slate-950 border-slate-800 text-slate-400 hover:border-slate-700'
                  }`}
                >
                  <strong className="block text-xs font-bold text-slate-100">SSHv2 (View Shell)</strong>
                  <span className="text-[10px] text-slate-400 block mt-0.5">Usuário de leitura limitada (show only)</span>
                </button>
              </div>
            </div>

            {/* Common Connection Fields: Port & View User */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              <div>
                <label className="text-slate-300 font-semibold block mb-1">Porta Alvo</label>
                <input
                  type="number"
                  required
                  value={targetPort}
                  onChange={(e) => setTargetPort(Number(e.target.value))}
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-slate-100 focus:outline-none focus:border-cyan-500 font-mono"
                />
              </div>

              <div className="sm:col-span-2">
                <label className="text-slate-300 font-semibold block mb-1">
                  Usuário de Leitura (View-Only / Security Name) *
                </label>
                <input
                  type="text"
                  required
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="snmp_auditor, view_user..."
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-slate-100 focus:outline-none focus:border-cyan-500 font-mono"
                />
              </div>
            </div>

            {/* SNMPv3 Detailed Security Fields */}
            {protocol === 'snmp_v3' && (
              <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 space-y-3">
                <div className="flex items-center justify-between text-xs border-b border-slate-800/80 pb-2">
                  <span className="font-bold text-cyan-400 flex items-center gap-1.5">
                    <Lock className="w-3.5 h-3.5" />
                    <span>Configuração de Autenticação e Privacidade SNMPv3 (RFC 3414)</span>
                  </span>

                  <button
                    type="button"
                    onClick={() => setShowSecrets(!showSecrets)}
                    className="flex items-center gap-1 text-[11px] text-slate-400 hover:text-slate-200"
                  >
                    {showSecrets ? <EyeOff className="w-3 h-3" /> : <Eye className="w-3 h-3" />}
                    <span>{showSecrets ? 'Ocultar Senhas' : 'Exibir Senhas'}</span>
                  </button>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div>
                    <label className="text-slate-400 block mb-1">Nível de Segurança (Security Level)</label>
                    <select
                      value={snmpSecLevel}
                      onChange={(e) => setSnmpSecLevel(e.target.value as any)}
                      className="w-full px-3 py-1.5 bg-slate-900 border border-slate-700 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
                    >
                      <option value="authPriv">authPriv (Autenticado + Criptografado - Recomendado)</option>
                      <option value="authNoPriv">authNoPriv (Apenas Autenticação)</option>
                      <option value="noAuthNoPriv">noAuthNoPriv (Sem Auth/Priv)</option>
                    </select>
                  </div>

                  <div>
                    <label className="text-slate-400 block mb-1">Protocolo de Autenticação (Auth)</label>
                    <select
                      value={snmpAuthProtocol}
                      onChange={(e) => setSnmpAuthProtocol(e.target.value as any)}
                      className="w-full px-3 py-1.5 bg-slate-900 border border-slate-700 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
                    >
                      <option value="SHA">SHA-1 (Padrão Cisco / MikroTik)</option>
                      <option value="SHA-256">SHA-256 (Alto Nível)</option>
                      <option value="MD5">MD5 (Legado)</option>
                    </select>
                  </div>
                </div>

                {snmpSecLevel !== 'noAuthNoPriv' && (
                  <div>
                    <label className="text-slate-400 block mb-1">Senha / Passphrase de Autenticação (Auth Key)</label>
                    <input
                      type={showSecrets ? 'text' : 'password'}
                      value={snmpAuthPassphrase}
                      onChange={(e) => setSnmpAuthPassphrase(e.target.value)}
                      placeholder="Chave secreta de autenticação..."
                      className="w-full px-3 py-1.5 bg-slate-900 border border-slate-700 rounded-lg text-slate-100 focus:outline-none focus:border-cyan-500 font-mono"
                    />
                  </div>
                )}

                {snmpSecLevel === 'authPriv' && (
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-1">
                    <div>
                      <label className="text-slate-400 block mb-1">Algoritmo de Privacidade (Priv Ciphers)</label>
                      <select
                        value={snmpPrivProtocol}
                        onChange={(e) => setSnmpPrivProtocol(e.target.value as any)}
                        className="w-full px-3 py-1.5 bg-slate-900 border border-slate-700 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
                      >
                        <option value="AES">AES-128 (Padrão IEEE / IETF)</option>
                        <option value="AES-256">AES-256 (Forte)</option>
                        <option value="DES">DES (Legado 56-bit)</option>
                      </select>
                    </div>

                    <div>
                      <label className="text-slate-400 block mb-1">Senha de Criptografia / Privacidade (Priv Key)</label>
                      <input
                        type={showSecrets ? 'text' : 'password'}
                        value={snmpPrivPassphrase}
                        onChange={(e) => setSnmpPrivPassphrase(e.target.value)}
                        placeholder="Chave de cifragem AES..."
                        className="w-full px-3 py-1.5 bg-slate-900 border border-slate-700 rounded-lg text-slate-100 focus:outline-none focus:border-cyan-500 font-mono"
                      />
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* SNMPv2c Community Field */}
            {protocol === 'snmp_v2c' && (
              <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
                <label className="text-slate-300 font-semibold block">
                  Comunidade SNMP de Leitura (Read-Only Community) *
                </label>
                <div className="relative">
                  <input
                    type={showSecrets ? 'text' : 'password'}
                    required
                    value={snmpCommunity}
                    onChange={(e) => setSnmpCommunity(e.target.value)}
                    placeholder="public, monitoring_ro..."
                    className="w-full pl-3 pr-10 py-2 bg-slate-900 border border-slate-700 rounded-lg text-slate-100 focus:outline-none focus:border-cyan-500 font-mono"
                  />
                  <button
                    type="button"
                    onClick={() => setShowSecrets(!showSecrets)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-200"
                  >
                    {showSecrets ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                  </button>
                </div>
                <span className="text-[10px] text-slate-400">
                  Nunca utilize comunidades com permissão de escrita (RW). Utilize sempre perfis restritos à visualização de MIB-II.
                </span>
              </div>
            )}

            {/* SSH Password Field */}
            {protocol === 'ssh' && (
              <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
                <label className="text-slate-300 font-semibold block">
                  Senha do Usuário de Leitura SSH (View Operator)
                </label>
                <div className="relative">
                  <input
                    type={showSecrets ? 'text' : 'password'}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="Senha restrita a comandos de visualização..."
                    className="w-full pl-3 pr-10 py-2 bg-slate-900 border border-slate-700 rounded-lg text-slate-100 focus:outline-none focus:border-cyan-500 font-mono"
                  />
                  <button
                    type="button"
                    onClick={() => setShowSecrets(!showSecrets)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-200"
                  >
                    {showSecrets ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                  </button>
                </div>
              </div>
            )}

            {/* Notes / Purpose */}
            <div>
              <label className="text-slate-400 block mb-1">Anotações / Finalidade do Perfil</label>
              <input
                type="text"
                value={notes}
                onChange={(e) => setNotes(e.target.value)}
                placeholder="ex: Switch Core Rack A - Coleta de Portas e Chassi..."
                className="w-full px-3 py-1.5 bg-slate-950 border border-slate-700 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500 font-sans"
              />
            </div>

            {/* Live Nmap Command Preview */}
            <div className="p-3.5 rounded-xl bg-slate-950 border border-cyan-900/50 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-bold text-cyan-300 flex items-center gap-1.5">
                  <Terminal className="w-3.5 h-3.5" />
                  <span>Comando Nmap SNMP Gerado para o Diagnóstico:</span>
                </span>

                <button
                  type="button"
                  onClick={() => handleCopy(generatedNmapCommand, 'nmap-cmd')}
                  className="flex items-center gap-1 px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[10px] font-mono transition-colors"
                >
                  {copiedKey === 'nmap-cmd' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  <span>Copiar</span>
                </button>
              </div>

              <code className="text-[11px] font-mono text-cyan-200/90 break-all block leading-relaxed bg-slate-900/80 p-2.5 rounded-lg border border-slate-800">
                {generatedNmapCommand}
              </code>
            </div>

            {/* Submit & Action Buttons */}
            <div className="flex flex-col sm:flex-row items-center justify-between gap-3 pt-3 border-t border-slate-800">
              <div className="text-[11px] text-slate-400 flex items-center gap-1">
                <Info className="w-3.5 h-3.5 text-cyan-400" />
                <span>As senhas são armazenadas localmente com hash defensivo.</span>
              </div>

              <div className="flex items-center gap-2 w-full sm:w-auto justify-end">
                {onOpenKaliTerminal && (
                  <button
                    type="button"
                    onClick={() => onOpenKaliTerminal(generatedNmapCommand)}
                    className="px-3.5 py-2 bg-slate-800 hover:bg-slate-700 text-cyan-300 font-mono font-bold text-xs rounded-lg transition-colors flex items-center gap-1.5"
                    title="Executar imediatamente no terminal do Kali"
                  >
                    <Terminal className="w-3.5 h-3.5" />
                    <span>Rodar no Kali</span>
                  </button>
                )}

                <button
                  type="submit"
                  disabled={isSaving}
                  className="px-4 py-2 bg-cyan-400 hover:bg-cyan-300 disabled:opacity-75 text-slate-950 font-bold text-xs rounded-lg transition-all shadow-md flex items-center gap-1.5 cursor-pointer"
                >
                  {isSaving ? <RotateCw className="w-3.5 h-3.5 animate-spin" /> : <Plus className="w-3.5 h-3.5" />}
                  <span>Salvar Credencial Segura</span>
                </button>
              </div>
            </div>
          </form>
        </div>

        {/* Right Column: Active Credentials Vault & Discovered Hardware Inventory (5 cols) */}
        <div className="xl:col-span-5 space-y-4">
          <div className="flex items-center justify-between p-4 rounded-xl bg-slate-900 border border-slate-800">
            <div className="space-y-0.5">
              <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                <HardDrive className="w-4 h-4 text-cyan-400" />
                <span>Credenciais & Inventários de Hardware</span>
              </h3>
              <p className="text-xs text-slate-400">
                Dispositivos autenticados para consultas SNMP detalhadas.
              </p>
            </div>
            <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-slate-800 text-cyan-400 border border-slate-700">
              {credentials.length}
            </span>
          </div>

          <div className="space-y-3">
            {credentials.length === 0 ? (
              <div className="p-8 text-center rounded-xl bg-slate-900/60 border border-slate-800 text-xs text-slate-500 space-y-2">
                <Key className="w-8 h-8 text-slate-600 mx-auto" />
                <p>Nenhuma credencial cadastrada ainda. Utilize o formulário ao lado para cadastrar usuários View-Only ou SNMPv3.</p>
              </div>
            ) : (
              credentials.map((cred) => (
                <div
                  key={cred.id}
                  className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3 hover:border-slate-700 transition-all shadow-md"
                >
                  {/* Card Header */}
                  <div className="flex items-start justify-between gap-2">
                    <div className="space-y-1">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase border ${
                          cred.protocol === 'snmp_v3' ? 'bg-cyan-950 text-cyan-300 border-cyan-700' :
                          cred.protocol === 'snmp_v2c' ? 'bg-indigo-950 text-indigo-300 border-indigo-700' :
                          'bg-slate-800 text-slate-200 border-slate-700'
                        }`}>
                          {cred.protocol.replace('_', ' ')}
                        </span>
                        
                        <strong className="text-xs font-mono text-slate-100">{cred.targetIp}:{cred.targetPort}</strong>

                        {cred.profileName && (
                          <span className="text-[10px] text-slate-400 bg-slate-950 px-1.5 py-0.2 rounded border border-slate-800">
                            {cred.profileName}
                          </span>
                        )}
                      </div>

                      <div className="text-[11px] text-slate-400 flex items-center gap-2 font-mono">
                        <span>Usuário View: <strong className="text-slate-200">{cred.username}</strong></span>
                        <span className="text-slate-600">·</span>
                        <span className={cred.authStatus === 'valid' ? 'text-emerald-400 font-bold' : cred.authStatus === 'failed' ? 'text-rose-400' : 'text-slate-500'}>
                          {cred.authStatus === 'valid' ? '● Acesso Validado' : cred.authStatus === 'failed' ? '● Falha de Conexão' : '● Não testado'}
                        </span>
                      </div>
                    </div>

                    <div className="flex items-center gap-1.5 shrink-0">
                      <button
                        onClick={() => handleDeleteCred(cred.id)}
                        className="p-1.5 rounded-lg bg-slate-950 hover:bg-rose-950/60 text-slate-400 hover:text-rose-400 transition-colors"
                        title="Remover Credencial"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </div>

                  {/* Discovered Hardware Info (if queried) */}
                  {cred.hardwareInfo ? (
                    <div className="p-3 rounded-lg bg-slate-950 border border-emerald-900/40 space-y-2 text-xs">
                      <div className="flex items-center justify-between">
                        <span className="text-[11px] font-bold text-emerald-400 flex items-center gap-1.5">
                          <CheckCircle2 className="w-3.5 h-3.5" />
                          <span>Inventário de Hardware Levantado via SNMP:</span>
                        </span>
                        <span className="text-[10px] font-mono text-slate-400">
                          {cred.hardwareInfo.interfacesCount} portas ativas
                        </span>
                      </div>

                      <div className="grid grid-cols-2 gap-2 text-[11px] font-mono">
                        <div className="p-2 rounded bg-slate-900/80 border border-slate-800">
                          <span className="text-[10px] text-slate-500 block uppercase">Chassi / Modelo</span>
                          <span className="text-slate-200 font-semibold">{cred.hardwareInfo.chassisModel}</span>
                        </div>
                        <div className="p-2 rounded bg-slate-900/80 border border-slate-800">
                          <span className="text-[10px] text-slate-500 block uppercase">Nº de Série (SN)</span>
                          <span className="text-cyan-300 font-semibold">{cred.hardwareInfo.serialNumber}</span>
                        </div>
                      </div>

                      <div className="p-2 rounded bg-slate-900/80 border border-slate-800 text-[10px] font-mono text-slate-300">
                        <span className="text-slate-500 block uppercase text-[9px]">SysDescr (MIB-II)</span>
                        <span className="break-all">{cred.hardwareInfo.sysDescr}</span>
                      </div>

                      <div className="flex items-center justify-between text-[10px] text-slate-400 font-mono">
                        <span>Uptime: <strong className="text-slate-300">{cred.hardwareInfo.uptime}</strong></span>
                        <span>Firmware: <strong className="text-slate-300">{cred.hardwareInfo.firmwareVersion}</strong></span>
                      </div>
                    </div>
                  ) : (
                    <div className="p-2.5 rounded-lg bg-slate-950/60 border border-slate-800/80 text-[11px] text-slate-500 flex items-center justify-between">
                      <span>Nenhum levantamento SNMP executado para esta credencial ainda.</span>
                    </div>
                  )}

                  {/* Card Actions */}
                  <div className="flex items-center justify-between gap-2 pt-2 border-t border-slate-800/80 text-xs">
                    <span className="text-[10px] text-slate-500 font-mono truncate">
                      Último teste: {cred.lastTested || 'Ainda não executado'}
                    </span>

                    <div className="flex items-center gap-1.5 shrink-0">
                      <button
                        onClick={() => handleTestCred(cred.id)}
                        disabled={isTestingId === cred.id}
                        className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-[11px] font-mono transition-colors flex items-center gap-1 cursor-pointer"
                        title="Testar Conectividade de Porta"
                      >
                        {isTestingId === cred.id ? <RotateCw className="w-3 h-3 animate-spin" /> : <Activity className="w-3 h-3 text-cyan-400" />}
                        <span>Testar Porta</span>
                      </button>

                      <button
                        onClick={() => handleRunSnmpQuery(cred.id)}
                        disabled={isQueryingId === cred.id}
                        className="px-2.5 py-1 rounded bg-cyan-950 hover:bg-cyan-900 text-cyan-300 border border-cyan-800 text-[11px] font-mono font-bold transition-colors flex items-center gap-1 cursor-pointer"
                        title="Executar Consulta SNMP para Levantamento de Hardware"
                      >
                        {isQueryingId === cred.id ? <RotateCw className="w-3 h-3 animate-spin" /> : <Zap className="w-3 h-3 fill-cyan-400 text-cyan-400" />}
                        <span>Consulta SNMP</span>
                      </button>

                      {onOpenKaliTerminal && (
                        <button
                          onClick={() => onOpenKaliTerminal(`nmap -sU -p ${cred.targetPort || 161} --script snmp-info,snmp-interfaces,snmp-sysdescr ${cred.targetIp}`)}
                          className="p-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors"
                          title="Abrir no Terminal Nmap do Kali"
                        >
                          <Terminal className="w-3 h-3" />
                        </button>
                      )}
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
