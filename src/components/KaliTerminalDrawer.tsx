import React, { useState } from 'react';
import { Terminal, X, Play, Copy, Check, RotateCcw, Loader2, Info, HelpCircle, ShieldAlert } from 'lucide-react';

interface KaliTerminalDrawerProps {
  isOpen: boolean;
  onClose: () => void;
  command: string;
  output: string;
  isRunning: boolean;
  onRunCommand: (cmd: string) => void;
  isLiveKaliConnected?: boolean;
}

export const KaliTerminalDrawer: React.FC<KaliTerminalDrawerProps> = ({
  isOpen,
  onClose,
  command,
  output,
  isRunning,
  onRunCommand,
  isLiveKaliConnected
}) => {
  const [currentCmd, setCurrentCmd] = useState(command);
  const [copied, setCopied] = useState(false);
  const [showTroubleshooting, setShowTroubleshooting] = useState(false);

  React.useEffect(() => {
    if (command) {
      setCurrentCmd(command);
    }
  }, [command]);

  if (!isOpen) return null;

  const handleCopy = () => {
    navigator.clipboard.writeText(output || currentCmd);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const QUICK_COMMANDS = [
    { label: 'Nmap Stealth (-Pn)', cmd: 'sudo nmap -sV -sC -O -Pn 192.168.1.1' },
    { label: 'Nmap Rápido (-F -Pn)', cmd: 'sudo nmap -F -Pn 192.168.1.1' },
    { label: 'Iptables (Regras Ativas)', cmd: 'sudo iptables -L INPUT -v -n --line-numbers' },
    { label: 'Tabela ARP do Kernel', cmd: 'cat /proc/net/arp' },
    { label: 'Rotas do Kernel', cmd: 'ip route show' },
    { label: 'Tcpdump (10 pacotes)', cmd: 'sudo tcpdump -i any -c 10 -nn' },
  ];

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-4 bg-slate-950/85 backdrop-blur-md animate-fadeIn">
      <div className="relative w-full max-w-4xl bg-slate-950 border border-slate-800 rounded-xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
        {/* Header */}
        <div className="px-5 py-3 border-b border-slate-800 flex items-center justify-between bg-slate-900/70">
          <div className="flex items-center gap-2.5">
            <div className="p-1.5 rounded-md bg-cyan-950 text-cyan-400 border border-cyan-800">
              <Terminal className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
                <span>Terminal Integrado do Kali Linux</span>
                <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded border ${
                  isLiveKaliConnected
                    ? 'bg-emerald-950 text-emerald-300 border-emerald-800'
                    : 'bg-cyan-950 text-cyan-300 border-cyan-800'
                }`}>
                  {isLiveKaliConnected ? '● HOST KALI AO VIVO (Porta 8080)' : 'MODO STANDBY / PORTAINER'}
                </span>
              </h3>
              <p className="text-[11px] text-slate-400">
                Execução de ações sugeridas pelo painel diretamente no terminal do host Kali.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => setShowTroubleshooting(!showTroubleshooting)}
              className={`p-1.5 rounded text-xs flex items-center gap-1 transition-colors ${
                showTroubleshooting ? 'bg-amber-950 text-amber-300 border border-amber-800' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
              }`}
              title="Ajuda e diagnóstico de retornos comuns (Host down, -Pn, permissões)"
            >
              <HelpCircle className="w-4 h-4" />
              <span className="hidden sm:inline text-[11px]">Diagnóstico de Erros</span>
            </button>
            <button
              onClick={handleCopy}
              className="p-1.5 text-slate-400 hover:text-slate-200 rounded hover:bg-slate-800 transition-colors"
              title="Copiar saída do terminal"
            >
              {copied ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
            </button>
            <button
              onClick={onClose}
              className="p-1.5 text-slate-400 hover:text-slate-200 rounded hover:bg-slate-800 transition-colors"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Quick Diagnostic / Troubleshooting Banner */}
        {showTroubleshooting && (
          <div className="p-3.5 bg-slate-900 border-b border-slate-800 text-xs text-slate-300 space-y-2 animate-fadeIn">
            <div className="flex items-center gap-1.5 text-amber-400 font-semibold">
              <Info className="w-4 h-4" />
              <span>Guia Rápido: Resolvendo Retornos Comuns no Terminal do Kali</span>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-2.5 text-[11px]">
              <div className="p-2.5 rounded bg-slate-950 border border-slate-800">
                <span className="font-semibold text-rose-300 block mb-0.5">1. "Host seems down... try -Pn"</span>
                <p className="text-slate-400 leading-relaxed">
                  O dispositivo bloqueia ping ICMP (muito comum em Windows, celulares e firewalls). Adicione sempre a flag <code className="text-cyan-400">-Pn</code> ao comando Nmap para forçar o scan sem ping prévio.
                </p>
              </div>
              <div className="p-2.5 rounded bg-slate-950 border border-slate-800">
                <span className="font-semibold text-amber-300 block mb-0.5">2. "requires root privileges"</span>
                <p className="text-slate-400 leading-relaxed">
                  Scans avançados de SO (<code className="text-cyan-400">-O</code>) ou SYN scan requerem permissão root. Sempre inicie com <code className="text-emerald-400">sudo</code>.
                </p>
              </div>
              <div className="p-2.5 rounded bg-slate-950 border border-slate-800">
                <span className="font-semibold text-cyan-300 block mb-0.5">3. "No such device (eth0)"</span>
                <p className="text-slate-400 leading-relaxed">
                  Se a interface for WiFi (<code className="text-cyan-400">wlan0</code>) ou VMware (<code className="text-cyan-400">ens33</code>), use <code className="text-emerald-400">-i any</code> no tcpdump ou informe a interface correta.
                </p>
              </div>
            </div>
          </div>
        )}

        {/* Quick Presets Bar */}
        <div className="px-3 py-2 bg-slate-950 border-b border-slate-800/80 flex items-center gap-1.5 overflow-x-auto text-[11px]">
          <span className="text-slate-500 whitespace-nowrap mr-1">Atalhos Rápidos:</span>
          {QUICK_COMMANDS.map((item) => (
            <button
              key={item.label}
              onClick={() => {
                setCurrentCmd(item.cmd);
                onRunCommand(item.cmd);
              }}
              className="px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-slate-300 hover:text-cyan-300 hover:border-cyan-800 whitespace-nowrap transition-colors font-mono"
            >
              {item.label}
            </button>
          ))}
        </div>

        {/* Command Input Bar */}
        <div className="p-3 bg-slate-900/50 border-b border-slate-800 flex items-center gap-2">
          <span className="text-xs font-mono text-cyan-400 select-none font-bold">kali@root#</span>
          <input
            type="text"
            value={currentCmd}
            onChange={(e) => setCurrentCmd(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && !isRunning && currentCmd.trim()) {
                onRunCommand(currentCmd);
              }
            }}
            className="flex-1 bg-slate-950 border border-slate-800 px-3 py-1.5 rounded text-xs font-mono text-slate-100 focus:outline-none focus:border-cyan-500 shadow-inner"
            placeholder="Digite o comando para executar no Kali Linux..."
          />
          <button
            onClick={() => onRunCommand(currentCmd)}
            disabled={isRunning || !currentCmd.trim()}
            className="px-4 py-1.5 rounded text-xs font-semibold bg-cyan-400 text-slate-950 hover:bg-cyan-300 transition-colors disabled:opacity-50 flex items-center gap-1.5 shrink-0 shadow-sm"
          >
            {isRunning ? (
              <>
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
                <span>Executando...</span>
              </>
            ) : (
              <>
                <Play className="w-3.5 h-3.5 fill-slate-950" />
                <span>Executar no Kali</span>
              </>
            )}
          </button>
        </div>

        {/* Terminal Screen */}
        <div className="p-4 bg-black font-mono text-xs overflow-y-auto flex-1 min-h-[320px] max-h-[460px] text-slate-300 selection:bg-cyan-500/30">
          <div className="text-slate-500 mb-2 font-mono">
            ┌──(root㉿kali-soc)-[/opt/netsentry]<br />
            └─# {currentCmd}
          </div>

          {isRunning && (
            <div className="flex items-center gap-2 text-cyan-400 my-3 p-2 bg-cyan-950/20 border border-cyan-800/40 rounded">
              <Loader2 className="w-4 h-4 animate-spin text-cyan-400" />
              <span>Enviando comando para o terminal do Kali via daemon (PID Host / nsenter)...</span>
            </div>
          )}

          {output ? (
            <pre className="whitespace-pre-wrap leading-relaxed text-emerald-400 font-mono">
              <code>{output}</code>
            </pre>
          ) : !isRunning ? (
            <div className="text-slate-600 italic py-6 text-center">
              Pressione "Executar no Kali" acima ou escolha uma ação sugerida no painel para ver a saída em tempo real.
            </div>
          ) : null}
        </div>

        {/* Footer info */}
        <div className="px-4 py-2.5 bg-slate-950 border-t border-slate-800 flex items-center justify-between text-[11px] text-slate-500">
          <div className="flex items-center gap-3">
            <span>Namespace: <strong className="text-slate-400">PID 1 (Host Kali Linux)</strong></span>
            <span aria-hidden="true">·</span>
            <span>Permissões: <strong className="text-emerald-400">root / privileged</strong></span>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => onRunCommand(currentCmd)}
              disabled={isRunning || !currentCmd.trim()}
              className="px-2.5 py-1 bg-slate-900 border border-slate-800 text-slate-300 rounded hover:bg-slate-800 hover:text-white transition-colors"
            >
              Reexecutar
            </button>
            <button
              onClick={onClose}
              className="px-3 py-1 bg-slate-800 text-slate-200 rounded hover:bg-slate-700 transition-colors font-medium"
            >
              Fechar
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
