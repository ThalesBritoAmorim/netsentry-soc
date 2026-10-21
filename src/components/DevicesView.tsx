import React, { useState } from 'react';
import { NetworkDevice, DeviceTrustLevel, DeviceType } from '../types';
import { 
  Wifi, 
  Search, 
  ShieldCheck, 
  ShieldAlert, 
  Radio, 
  Terminal, 
  HardDrive, 
  Server, 
  Laptop, 
  Camera, 
  HelpCircle, 
  Activity, 
  Lock, 
  Unlock,
  AlertOctagon,
  X,
  ExternalLink,
  Copy,
  Check,
  Play,
  Zap,
  Info
} from 'lucide-react';

interface DevicesViewProps {
  devices: NetworkDevice[];
  onSetTrustLevel: (deviceId: string, level: DeviceTrustLevel) => void;
  onScanSubnet: () => void;
  onOpenKaliTerminal?: (cmd: string) => void;
}

export const DevicesView: React.FC<DevicesViewProps> = ({
  devices,
  onSetTrustLevel,
  onScanSubnet,
  onOpenKaliTerminal
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [filterType, setFilterType] = useState<string>('all');
  const [filterTrust, setFilterTrust] = useState<string>('all');
  const [selectedDevice, setSelectedDevice] = useState<NetworkDevice | null>(null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const filteredDevices = devices.filter((dev) => {
    const matchesSearch = 
      dev.ip.toLowerCase().includes(searchTerm.toLowerCase()) ||
      dev.hostname.toLowerCase().includes(searchTerm.toLowerCase()) ||
      dev.mac.toLowerCase().includes(searchTerm.toLowerCase()) ||
      dev.vendor.toLowerCase().includes(searchTerm.toLowerCase());

    const matchesType = filterType === 'all' || dev.deviceType === filterType;
    const matchesTrust = filterTrust === 'all' || dev.trustLevel === filterTrust;

    return matchesSearch && matchesType && matchesTrust;
  });

  const getDeviceIcon = (type: DeviceType) => {
    switch (type) {
      case 'gateway': return <Wifi className="w-4 h-4 text-cyan-400" />;
      case 'kali_node': return <Terminal className="w-4 h-4 text-emerald-400" />;
      case 'server': return <Server className="w-4 h-4 text-indigo-400" />;
      case 'workstation': return <Laptop className="w-4 h-4 text-slate-300" />;
      case 'iot': return <Camera className="w-4 h-4 text-amber-400" />;
      default: return <HelpCircle className="w-4 h-4 text-rose-400" />;
    }
  };

  const getDeviceLabel = (type: DeviceType) => {
    switch (type) {
      case 'gateway': return 'Gateway / Router';
      case 'kali_node': return 'Kali Linux SOC';
      case 'server': return 'Servidor / NAS';
      case 'workstation': return 'Estação de Trabalho';
      case 'iot': return 'Câmera / Dispositivo IoT';
      default: return 'Desconhecido / Rogue';
    }
  };

  return (
    <div className="space-y-6">
      {/* 1. Header & Actions */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-base font-semibold text-slate-100 flex items-center gap-2">
            <span>Inventário & Mapa de Dispositivos Conectados</span>
            <span className="text-xs text-slate-400 font-mono">({devices.length} hosts catalogados)</span>
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Monitoramento de endereços MAC, fabricantes OUI, portas abertas e postura de segurança na sub-rede.
          </p>
        </div>

        <button
          onClick={onScanSubnet}
          className="flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-semibold text-slate-950 bg-cyan-400 hover:bg-cyan-300 transition-colors shadow-sm self-start sm:self-auto"
        >
          <Radio className="w-3.5 h-3.5" />
          <span>Escanear Sub-rede (ARP Sweep)</span>
        </button>
      </div>

      {/* 2. Filters & Search Bar */}
      <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
          {/* Search Input */}
          <div className="relative flex-1">
            <Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-500" />
            <input
              type="text"
              placeholder="Buscar por IP, MAC, hostname ou fabricante..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-9 pr-4 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
            />
          </div>

          {/* Type Filter */}
          <div className="flex items-center gap-1.5 overflow-x-auto text-xs">
            <span className="text-slate-500 whitespace-nowrap">Tipo:</span>
            {['all', 'gateway', 'kali_node', 'server', 'workstation', 'iot', 'unknown'].map((t) => (
              <button
                key={t}
                onClick={() => setFilterType(t)}
                className={`px-2.5 py-1 rounded-md capitalize whitespace-nowrap transition-colors ${
                  filterType === t ? 'bg-slate-800 text-slate-100 font-medium' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {t === 'all' ? 'Todos' : t === 'kali_node' ? 'Kali SOC' : t}
              </button>
            ))}
          </div>
        </div>

        {/* Trust Filter Row */}
        <div className="flex items-center gap-2 pt-2 border-t border-slate-800/80 text-xs">
          <span className="text-slate-500">Confiabilidade:</span>
          {[
            { id: 'all', label: 'Todos' },
            { id: 'trusted', label: 'Confiáveis' },
            { id: 'unverified', label: 'Não Verificados' },
            { id: 'quarantined', label: 'Em Quarentena' },
            { id: 'blocked', label: 'Bloqueados' }
          ].map((item) => (
            <button
              key={item.id}
              onClick={() => setFilterTrust(item.id)}
              className={`px-2.5 py-0.5 rounded transition-colors ${
                filterTrust === item.id ? 'bg-slate-800 text-cyan-300 font-semibold' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {item.label}
            </button>
          ))}
        </div>
      </div>

      {/* 3. Devices Table */}
      <div className="rounded-xl border border-slate-800 bg-slate-900 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950/80 text-slate-400 border-b border-slate-800 uppercase font-mono">
              <tr>
                <th className="py-3 px-4">Dispositivo / Host</th>
                <th className="py-3 px-4">Endereço IP & MAC</th>
                <th className="py-3 px-4">Fabricante (OUI)</th>
                <th className="py-3 px-4">Portas Abertas</th>
                <th className="py-3 px-4">Status & Confiança</th>
                <th className="py-3 px-4 text-right">Risco</th>
                <th className="py-3 px-4 text-center">Ações</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono text-slate-300">
              {filteredDevices.map((dev) => (
                <tr 
                  key={dev.id} 
                  className="hover:bg-slate-800/40 transition-colors cursor-pointer"
                  onClick={() => setSelectedDevice(dev)}
                >
                  <td className="py-3.5 px-4 font-sans">
                    <div className="flex items-center gap-2.5">
                      <div className="p-1.5 rounded-md bg-slate-950 border border-slate-800 shrink-0">
                        {getDeviceIcon(dev.deviceType)}
                      </div>
                      <div>
                        <div className="font-semibold text-slate-100 flex items-center gap-1.5">
                          <span>{dev.hostname}</span>
                          {dev.id === 'dev-2' && (
                            <span className="text-[10px] font-mono bg-cyan-950 text-cyan-300 px-1 rounded border border-cyan-800">
                              ESTE HOST
                            </span>
                          )}
                        </div>
                        <div className="text-[11px] text-slate-500 font-sans">
                          {getDeviceLabel(dev.deviceType)}
                        </div>
                      </div>
                    </div>
                  </td>

                  <td className="py-3.5 px-4">
                    <div className="text-slate-100 font-bold">{dev.ip}</div>
                    <div className="text-slate-500 text-[11px]">{dev.mac}</div>
                  </td>

                  <td className="py-3.5 px-4 font-sans text-slate-300">
                    {dev.vendor}
                  </td>

                  <td className="py-3.5 px-4">
                    <div className="flex items-center gap-1 flex-wrap">
                      {dev.openPorts.length > 0 ? (
                        dev.openPorts.map((p) => (
                          <span
                            key={p.port}
                            className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${
                              p.risk === 'critical' ? 'bg-rose-950 text-rose-300 border border-rose-800' :
                              p.risk === 'high' ? 'bg-amber-950 text-amber-300 border border-amber-800' :
                              'bg-slate-950 text-slate-300 border border-slate-800'
                            }`}
                            title={`${p.service} - Risco ${p.risk}`}
                          >
                            {p.port}/{p.service}
                          </span>
                        ))
                      ) : (
                        <span className="text-slate-500 font-sans">Nenhuma detectada</span>
                      )}
                    </div>
                  </td>

                  <td className="py-3.5 px-4 font-sans">
                    <span className={`inline-block text-[11px] font-medium px-2 py-0.5 rounded ${
                      dev.trustLevel === 'trusted' ? 'bg-emerald-950/70 text-emerald-300 border border-emerald-800/60' :
                      dev.trustLevel === 'quarantined' ? 'bg-amber-950/70 text-amber-300 border border-amber-800/60' :
                      dev.trustLevel === 'blocked' ? 'bg-rose-950/70 text-rose-300 border border-rose-800/60' :
                      'bg-slate-800 text-slate-300'
                    }`}>
                      {dev.trustLevel === 'trusted' ? 'Confiável' :
                       dev.trustLevel === 'quarantined' ? 'Em Quarentena' :
                       dev.trustLevel === 'blocked' ? 'Bloqueado' : 'Não Verificado'}
                    </span>
                  </td>

                  <td className="py-3.5 px-4 text-right">
                    <div className={`font-bold tabular-nums ${
                      dev.threatScore > 70 ? 'text-rose-400' :
                      dev.threatScore > 30 ? 'text-amber-400' : 'text-emerald-400'
                    }`}>
                      {dev.threatScore}/100
                    </div>
                  </td>

                  <td className="py-3.5 px-4 text-center font-sans" onClick={(e) => e.stopPropagation()}>
                    <div className="flex items-center justify-center gap-1">
                      {dev.trustLevel !== 'trusted' && (
                        <button
                          onClick={() => onSetTrustLevel(dev.id, 'trusted')}
                          className="p-1 text-slate-400 hover:text-emerald-400 hover:bg-slate-800 rounded"
                          title="Marcar como Confiável"
                        >
                          <ShieldCheck className="w-4 h-4" />
                        </button>
                      )}
                      {dev.trustLevel !== 'quarantined' && (
                        <button
                          onClick={() => onSetTrustLevel(dev.id, 'quarantined')}
                          className="p-1 text-slate-400 hover:text-amber-400 hover:bg-slate-800 rounded"
                          title="Enviar para Quarentena"
                        >
                          <Lock className="w-4 h-4" />
                        </button>
                      )}
                      {dev.trustLevel !== 'blocked' && (
                        <button
                          onClick={() => onSetTrustLevel(dev.id, 'blocked')}
                          className="p-1 text-slate-400 hover:text-rose-400 hover:bg-slate-800 rounded"
                          title="Bloquear no Firewall (Netfilter)"
                        >
                          <AlertOctagon className="w-4 h-4" />
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* 4. Device Inspector Drawer / Modal */}
      {selectedDevice && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-fadeIn">
          <div className="relative w-full max-w-2xl bg-slate-900 border border-slate-800 rounded-xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
            {/* Header */}
            <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between bg-slate-950/50">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-slate-900 border border-slate-800">
                  {getDeviceIcon(selectedDevice.deviceType)}
                </div>
                <div>
                  <h3 className="text-base font-semibold text-slate-100 flex items-center gap-2">
                    <span>{selectedDevice.hostname}</span>
                    <span className="text-xs font-mono text-slate-400">({selectedDevice.ip})</span>
                  </h3>
                  <div className="text-xs text-slate-400 mt-0.5">
                    {getDeviceLabel(selectedDevice.deviceType)} · {selectedDevice.vendor}
                  </div>
                </div>
              </div>
              <button
                onClick={() => setSelectedDevice(null)}
                className="p-1.5 text-slate-400 hover:text-slate-100 rounded-lg hover:bg-slate-800 transition-colors"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Body */}
            <div className="p-6 overflow-y-auto space-y-6 text-xs text-slate-300">
              {/* Telemetry Summary */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5">
                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                  <span className="text-slate-500 block">Endereço MAC</span>
                  <span className="font-mono text-slate-200 font-semibold">{selectedDevice.mac}</span>
                </div>
                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                  <span className="text-slate-500 block">Postura de Risco</span>
                  <span className="font-mono font-bold text-rose-400">{selectedDevice.threatScore}/100</span>
                </div>
                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                  <span className="text-slate-500 block">Dados Transmitidos</span>
                  <span className="font-mono text-slate-200">
                    {(selectedDevice.txBytes / 1024 / 1024).toFixed(1)} MB
                  </span>
                </div>
                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                  <span className="text-slate-500 block">Última Atividade</span>
                  <span className="text-emerald-400">{selectedDevice.lastSeen}</span>
                </div>
              </div>

              {/* Notes */}
              {selectedDevice.notes && (
                <div className="p-3 bg-slate-950/60 rounded-lg border border-slate-800">
                  <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block mb-1">
                    Auditoria & Observações de Rede
                  </span>
                  <p className="text-slate-300 leading-relaxed font-sans">
                    {selectedDevice.notes}
                  </p>
                </div>
              )}

              {/* Open Ports & Vulnerabilities */}
              <div className="space-y-2">
                <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block">
                  Portas Abertas & Detecção de Vulnerabilidades
                </span>
                {selectedDevice.openPorts.length > 0 ? (
                  <div className="border border-slate-800 rounded-lg overflow-hidden bg-slate-950">
                    <table className="w-full text-left font-mono">
                      <thead className="bg-slate-900/80 text-slate-400 text-[11px] border-b border-slate-800">
                        <tr>
                          <th className="py-2 px-3">Porta</th>
                          <th className="py-2 px-3">Serviço</th>
                          <th className="py-2 px-3">Versão / Banner</th>
                          <th className="py-2 px-3">Risco</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/60 text-[11px]">
                        {selectedDevice.openPorts.map((p) => (
                          <tr key={p.port}>
                            <td className="py-2 px-3 font-bold text-cyan-400">{p.port}</td>
                            <td className="py-2 px-3 text-slate-200">{p.service}</td>
                            <td className="py-2 px-3 text-slate-400">{p.version || p.cve || 'Padrão'}</td>
                            <td className="py-2 px-3">
                              <span className={`px-1.5 py-0.2 rounded font-semibold ${
                                p.risk === 'critical' ? 'bg-rose-950 text-rose-300' :
                                p.risk === 'high' ? 'bg-amber-950 text-amber-300' :
                                'bg-slate-800 text-slate-300'
                              }`}>
                                {p.risk.toUpperCase()}
                              </span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <p className="text-slate-500 italic">Nenhuma porta aberta detectada no scan.</p>
                )}
              </div>

              {/* Kali Linux Direct Forensic Commands with 1-Click Execution */}
              <div className="space-y-2.5">
                <div className="flex items-center justify-between">
                  <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block">
                    Comandos Forenses Rápidos no Terminal Kali Linux
                  </span>
                  <span className="text-[10px] text-cyan-400 font-mono">
                    1-Click: Executar Diretamente no Kali
                  </span>
                </div>

                <div className="space-y-2 font-mono text-xs">
                  {/* Scan 1: Completo com OS e Scripts (-Pn incluso) */}
                  <div className="p-2.5 bg-slate-950 rounded-lg border border-slate-800 space-y-2">
                    <div className="flex items-center justify-between font-sans text-[11px] text-slate-400">
                      <span className="font-semibold text-slate-200">Varredura Completa de Serviços & SO (-Pn)</span>
                      <span className="text-[10px] text-emerald-400 bg-emerald-950/60 px-1 rounded border border-emerald-800/60">Sem Ping (Evita bloqueio)</span>
                    </div>
                    <div className="flex items-center justify-between gap-2 bg-slate-900/80 p-1.5 rounded border border-slate-800">
                      <code className="text-cyan-400 truncate">sudo nmap -sV -sC -O -Pn {selectedDevice.ip}</code>
                      <div className="flex items-center gap-1 shrink-0">
                        <button
                          onClick={() => handleCopy(`sudo nmap -sV -sC -O -Pn ${selectedDevice.ip}`, 'nmap-full')}
                          className="text-slate-400 hover:text-cyan-400 p-1 rounded hover:bg-slate-800"
                          title="Copiar comando"
                        >
                          {copiedKey === 'nmap-full' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                        </button>
                        {onOpenKaliTerminal && (
                          <button
                            onClick={() => onOpenKaliTerminal(`sudo nmap -sV -sC -O -Pn ${selectedDevice.ip}`)}
                            className="flex items-center gap-1 px-2.5 py-1 bg-cyan-400 text-slate-950 font-sans font-semibold rounded text-[11px] hover:bg-cyan-300 transition-colors shadow-sm"
                            title="Disparar execução no terminal do host Kali"
                          >
                            <Play className="w-3 h-3 fill-slate-950" />
                            <span>Executar</span>
                          </button>
                        )}
                      </div>
                    </div>
                  </div>

                  {/* Scan 2: Rápido Top 100 portas (-F -Pn) */}
                  <div className="p-2.5 bg-slate-950 rounded-lg border border-slate-800 space-y-2">
                    <div className="flex items-center justify-between font-sans text-[11px] text-slate-400">
                      <span className="font-semibold text-slate-200">Varredura Expressa Rápida (Top 100 portas)</span>
                      <span className="text-[10px] text-cyan-400">Resposta em &lt; 5s</span>
                    </div>
                    <div className="flex items-center justify-between gap-2 bg-slate-900/80 p-1.5 rounded border border-slate-800">
                      <code className="text-cyan-400 truncate">sudo nmap -F -Pn {selectedDevice.ip}</code>
                      <div className="flex items-center gap-1 shrink-0">
                        <button
                          onClick={() => handleCopy(`sudo nmap -F -Pn ${selectedDevice.ip}`, 'nmap-fast')}
                          className="text-slate-400 hover:text-cyan-400 p-1 rounded hover:bg-slate-800"
                          title="Copiar comando"
                        >
                          {copiedKey === 'nmap-fast' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                        </button>
                        {onOpenKaliTerminal && (
                          <button
                            onClick={() => onOpenKaliTerminal(`sudo nmap -F -Pn ${selectedDevice.ip}`)}
                            className="flex items-center gap-1 px-2.5 py-1 bg-slate-800 text-slate-200 font-sans font-semibold rounded text-[11px] hover:bg-slate-700 transition-colors"
                            title="Disparar execução no terminal do host Kali"
                          >
                            <Play className="w-3 h-3" />
                            <span>Executar</span>
                          </button>
                        )}
                      </div>
                    </div>
                  </div>

                  {/* Scan 3: Captura de Tráfego do Host com tcpdump */}
                  <div className="p-2.5 bg-slate-950 rounded-lg border border-slate-800 space-y-2">
                    <div className="flex items-center justify-between font-sans text-[11px] text-slate-400">
                      <span className="font-semibold text-slate-200">Sniffer Forense Direto (tcpdump)</span>
                      <span className="text-[10px] text-slate-400">Interface auto (-i any)</span>
                    </div>
                    <div className="flex items-center justify-between gap-2 bg-slate-900/80 p-1.5 rounded border border-slate-800">
                      <code className="text-cyan-400 truncate">sudo tcpdump -i any host {selectedDevice.ip} -c 20 -n -v</code>
                      <div className="flex items-center gap-1 shrink-0">
                        <button
                          onClick={() => handleCopy(`sudo tcpdump -i any host ${selectedDevice.ip} -c 20 -n -v`, 'tcpdump')}
                          className="text-slate-400 hover:text-cyan-400 p-1 rounded hover:bg-slate-800"
                          title="Copiar comando"
                        >
                          {copiedKey === 'tcpdump' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                        </button>
                        {onOpenKaliTerminal && (
                          <button
                            onClick={() => onOpenKaliTerminal(`sudo tcpdump -i any host ${selectedDevice.ip} -c 20 -n -v`)}
                            className="flex items-center gap-1 px-2.5 py-1 bg-slate-800 text-slate-200 font-sans font-semibold rounded text-[11px] hover:bg-slate-700 transition-colors"
                            title="Disparar execução no terminal do host Kali"
                          >
                            <Play className="w-3 h-3" />
                            <span>Executar</span>
                          </button>
                        )}
                      </div>
                    </div>
                  </div>
                </div>

                {/* Troubleshooting / Diagnostic Callout for Nmap return */}
                <div className="p-3 bg-amber-950/20 border border-amber-800/40 rounded-lg space-y-1.5 font-sans">
                  <div className="flex items-center gap-1.5 text-amber-300 font-semibold text-xs">
                    <Info className="w-3.5 h-3.5 shrink-0" />
                    <span>Diagnóstico de Retorno no Host:</span>
                  </div>
                  <p className="text-[11px] text-slate-300 leading-relaxed">
                    Se você executou o scan e obteve <strong className="text-amber-200">"Host seems down... try -Pn"</strong>, é porque o host (ex: Windows ou celular) descarta requisições ping (ICMP). A opção acima com a flag <code className="text-cyan-300 font-mono">-Pn</code> força o Nmap a inspecionar as portas diretamente sem depender do ping!
                  </p>
                </div>
              </div>
            </div>

            {/* Footer */}
            <div className="px-6 py-4 border-t border-slate-800 bg-slate-950/80 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span className="text-slate-400">Alterar Confiabilidade:</span>
                <button
                  onClick={() => {
                    onSetTrustLevel(selectedDevice.id, 'trusted');
                    setSelectedDevice({ ...selectedDevice, trustLevel: 'trusted' });
                  }}
                  className={`px-2.5 py-1 rounded text-xs font-medium transition-colors ${
                    selectedDevice.trustLevel === 'trusted' ? 'bg-emerald-950 text-emerald-300 border border-emerald-800' : 'bg-slate-800 hover:bg-slate-700 text-slate-300'
                  }`}
                >
                  Confiável
                </button>
                <button
                  onClick={() => {
                    onSetTrustLevel(selectedDevice.id, 'quarantined');
                    setSelectedDevice({ ...selectedDevice, trustLevel: 'quarantined' });
                  }}
                  className={`px-2.5 py-1 rounded text-xs font-medium transition-colors ${
                    selectedDevice.trustLevel === 'quarantined' ? 'bg-amber-950 text-amber-300 border border-amber-800' : 'bg-slate-800 hover:bg-slate-700 text-slate-300'
                  }`}
                >
                  Quarentena
                </button>
                <button
                  onClick={() => {
                    onSetTrustLevel(selectedDevice.id, 'blocked');
                    setSelectedDevice({ ...selectedDevice, trustLevel: 'blocked' });
                  }}
                  className={`px-2.5 py-1 rounded text-xs font-medium transition-colors ${
                    selectedDevice.trustLevel === 'blocked' ? 'bg-rose-950 text-rose-300 border border-rose-800' : 'bg-slate-800 hover:bg-slate-700 text-slate-300'
                  }`}
                >
                  Bloquear
                </button>
              </div>

              <button
                onClick={() => setSelectedDevice(null)}
                className="px-4 py-2 rounded-lg text-xs font-medium text-slate-300 bg-slate-800 hover:bg-slate-700 transition-colors"
              >
                Concluir
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
