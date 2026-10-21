import React, { useState } from 'react';
import { ThreatCategory } from '../types';
import { 
  X, 
  Play, 
  Radio, 
  ShieldAlert, 
  Flame, 
  Search, 
  Globe, 
  Layers,
  Cpu,
  CheckCircle2
} from 'lucide-react';

interface AnomalySimulatorModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSimulate: (category: ThreatCategory) => void;
  autonomousMode: boolean;
}

export const AnomalySimulatorModal: React.FC<AnomalySimulatorModalProps> = ({
  isOpen,
  onClose,
  onSimulate,
  autonomousMode
}) => {
  const [lastSimulated, setLastSimulated] = useState<ThreatCategory | null>(null);

  if (!isOpen) return null;

  const scenarios: Array<{
    category: ThreatCategory;
    title: string;
    description: string;
    tool: string;
    icon: React.ReactNode;
    mitre: string;
  }> = [
    {
      category: 'arp_poisoning',
      title: 'Ataque ARP Poisoning / Spoofing',
      description: 'Simula o envio de 450 pacotes Gratuitous ARP forjando o MAC do Gateway 192.168.1.1 para interceptar credenciais.',
      tool: 'Kali Linux: arpspoof / ettercap',
      icon: <Layers className="w-5 h-5 text-amber-400" />,
      mitre: 'T1557.002'
    },
    {
      category: 'port_scan',
      title: 'Varredura Rápida de Portas TCP SYN',
      description: 'Simula varredura stealth (SYN scan) contra 180 portas do nó Kali Linux em menos de 2 segundos.',
      tool: 'Kali Linux: nmap -sS -p- -T4',
      icon: <Search className="w-5 h-5 text-cyan-400" />,
      mitre: 'T1046'
    },
    {
      category: 'dns_tunneling',
      title: 'Tunelamento DNS (Exfiltração de Dados)',
      description: 'Simula consultas DNS codificadas em Base64 com alta entropia (Shannon > 4.5) para canais C2 externos.',
      tool: 'Kali Linux: dnscat2 / iodine',
      icon: <Globe className="w-5 h-5 text-purple-400" />,
      mitre: 'T1071.004'
    },
    {
      category: 'ddos_flood',
      title: 'Surto Volumétrico de Tráfego (SYN Flood)',
      description: 'Gera rajada de mais de 1.400 pacotes/segundo simulando ataque de negação de serviço ao servidor de arquivos.',
      tool: 'Kali Linux: hping3 -S --flood -V',
      icon: <Flame className="w-5 h-5 text-rose-400" />,
      mitre: 'T1498.001'
    },
    {
      category: 'rogue_device',
      title: 'Injeção de Dispositivo Rogue Desconhecido',
      description: 'Conecta um novo MAC não autorizado solicitando IP via DHCP com portas de Telnet e ADB abertas.',
      tool: 'Kali Linux: macchanger / dhclient',
      icon: <ShieldAlert className="w-5 h-5 text-orange-400" />,
      mitre: 'T1200'
    }
  ];

  const handleRun = (category: ThreatCategory) => {
    setLastSimulated(category);
    onSimulate(category);
    setTimeout(() => {
      onClose();
    }, 600);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-fadeIn">
      <div className="relative w-full max-w-2xl bg-slate-900 border border-slate-800 rounded-xl shadow-2xl overflow-hidden flex flex-col">
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between bg-slate-950/50">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-cyan-950 text-cyan-400 border border-cyan-800">
              <Radio className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-base font-semibold text-slate-100">
                Simulador de Comportamento Anômalo & Ataques
              </h2>
              <p className="text-xs text-slate-400">
                Injete anomalias em tempo real para testar a detecção autônoma e os playbooks de mitigação.
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 text-slate-400 hover:text-slate-100 rounded-lg hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Status Callout */}
        <div className="px-6 py-3 bg-slate-950/40 border-b border-slate-800/80 flex items-center justify-between text-xs">
          <div className="flex items-center gap-2">
            <Cpu className="w-4 h-4 text-cyan-400" />
            <span className="text-slate-300">
              Modo de Defesa: <strong className={autonomousMode ? 'text-emerald-400' : 'text-slate-300'}>
                {autonomousMode ? 'Autônomo (Auto-Mitigação via Iptables em 1.2s)' : 'Supervisionado (Requer Aprovação Humana)'}
              </strong>
            </span>
          </div>
          <span className="text-slate-500 font-mono">
            Host: Kali Linux (promisc on)
          </span>
        </div>

        {/* Scenarios List */}
        <div className="p-6 space-y-3 max-h-[60vh] overflow-y-auto">
          {scenarios.map((sc) => {
            const isSelected = lastSimulated === sc.category;
            return (
              <div
                key={sc.category}
                className="p-4 rounded-lg bg-slate-950 border border-slate-800 hover:border-slate-700 transition-all flex items-start justify-between gap-4"
              >
                <div className="flex items-start gap-3.5">
                  <div className="p-2 rounded-md bg-slate-900 border border-slate-800 shrink-0 mt-0.5">
                    {sc.icon}
                  </div>
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <h3 className="text-sm font-semibold text-slate-100">{sc.title}</h3>
                      <span className="text-xs font-mono text-slate-500">· {sc.mitre}</span>
                    </div>
                    <p className="text-xs text-slate-400 leading-relaxed">
                      {sc.description}
                    </p>
                    <div className="text-xs text-slate-500 font-mono pt-1">
                      Emulador: {sc.tool}
                    </div>
                  </div>
                </div>

                <button
                  onClick={() => handleRun(sc.category)}
                  className={`px-3 py-1.5 rounded-lg text-xs font-medium shrink-0 flex items-center gap-1.5 transition-all ${
                    isSelected
                      ? 'bg-emerald-500 text-slate-950 font-semibold'
                      : 'bg-slate-800 hover:bg-cyan-500 hover:text-slate-950 text-slate-200'
                  }`}
                >
                  {isSelected ? (
                    <>
                      <CheckCircle2 className="w-3.5 h-3.5" />
                      <span>Injetado!</span>
                    </>
                  ) : (
                    <>
                      <Play className="w-3.5 h-3.5" />
                      <span>Disparar</span>
                    </>
                  )}
                </button>
              </div>
            );
          })}
        </div>

        {/* Footer */}
        <div className="px-6 py-3 border-t border-slate-800 bg-slate-950/60 flex items-center justify-end">
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-lg text-xs font-medium text-slate-300 bg-slate-800 hover:bg-slate-700 transition-colors"
          >
            Fechar
          </button>
        </div>
      </div>
    </div>
  );
};
