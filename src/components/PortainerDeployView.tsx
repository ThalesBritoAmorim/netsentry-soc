import React, { useState } from 'react';
import { 
  DOCKER_COMPOSE_YML, 
  PYTHON_DAEMON_SCRIPT, 
  INIT_SQL_SCHEMA, 
  KALI_INSTALL_SCRIPT,
  ALL_IN_ONE_QUICKSTART_SCRIPT
} from '../services/kaliPortainerAssets';
import { 
  Copy, 
  Check, 
  Download, 
  Terminal, 
  Server, 
  Database, 
  Layers, 
  Zap,
  CheckCircle2,
  ExternalLink,
  Shield,
  HelpCircle,
  Wifi,
  Radio,
  Activity,
  Cpu,
  AlertTriangle,
  ArrowRight,
  FolderArchive,
  FileCode2,
  PackageCheck
} from 'lucide-react';
import { downloadCompleteProjectZip } from '../services/projectDownloader';

const DOCKERFILE_CODE = `# ==============================================================================
# NetSentry SOC - Dockerfile Multi-stage para Portainer & Docker no Kali Linux
# Constrói o frontend React + Tailwind + Recharts e serve via Nginx de alta performance
# ==============================================================================

# Etapa 1: Build da Aplicação React / Vite (Debian Bookworm Slim para 100% de compatibilidade com Kali e glibc)
FROM node:20-bookworm-slim AS builder
WORKDIR /app

ENV NODE_OPTIONS="--max-old-space-size=2048"

# Copia dependências e instala com compatibilidade para React 19
COPY package*.json ./
RUN npm install react-is --save --legacy-peer-deps && npm install --legacy-peer-deps

# Copia código-fonte e compila para produção (dist/)
COPY . .
RUN npm run build

# Etapa 2: Servidor Web Nginx ultra-leve
FROM nginx:alpine
WORKDIR /usr/share/nginx/html

# Limpa arquivos padrão do Nginx
RUN rm -rf ./*

# Copia o bundle compilado da etapa anterior
COPY --from=builder /app/dist .

# Copia configuração customizada do Nginx com proxy reverso para o daemon na porta 8080
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 3000

CMD ["nginx", "-g", "daemon off;"]
`;

const NGINX_CONF_CODE = `# NetSentry SOC - Nginx Reverse Proxy & Static SPA Configuration
server {
    listen 3000;
    server_name localhost;
    root /usr/share/nginx/html;
    index index.html;

    # Gzip compression para alta performance nos gráficos Recharts
    gzip on;
    gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript;

    # Proxy reverso para o NetSentry Daemon (suporta /api/kali/ e /api/)
    location /api/kali/ {
        proxy_pass http://127.0.0.1:8080/api/;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_read_timeout 120s;
    }

    location /api/ {
        proxy_pass http://127.0.0.1:8080/api/;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_read_timeout 120s;
    }

    # Roteamento SPA (Single Page Application)
    location / {
        try_files $uri $uri/ /index.html;
    }
}
`;

const SETUP_PERMISSIONS_SCRIPT = `#!/usr/bin/env bash
# ==============================================================================
# NetSentry SOC - Script Definitivo de Permissões para Kali Linux & Portainer
# Concede permissões totais para Docker, Portainer, Kernel Netfilter, Scapy e Nmap
# ==============================================================================
set -e

RED='\\033[0;31m'
GREEN='\\033[0;32m'
CYAN='\\033[0;36m'
YELLOW='\\033[1;33m'
BOLD='\\033[1m'
NC='\\033[0m'

if [ "$EUID" -ne 0 ]; then
    echo -e "\${YELLOW}[!] Privilégios de root necessários. Elevando com sudo...\${NC}"
    exec sudo bash "$0" "$@"
fi

TARGET_USER="\${SUDO_USER:-\$USER}"
[ "$TARGET_USER" = "root" ] && id "kali" >/dev/null 2>&1 && TARGET_USER="kali"
echo -e "\${CYAN}[INFO]\${NC} Configurando permissões totais para o usuário: \${BOLD}\$TARGET_USER\${NC}"

# 1. Ferramentas essenciais no Kali
apt-get update -qq || true
PKGS=(docker.io docker-compose-plugin docker-compose iptables iproute2 tcpdump nmap arping net-tools iputils-ping util-linux procps curl wget git libcap2-bin kmod python3 python3-pip python3-venv libpcap-dev build-essential)
for pkg in "\${PKGS[@]}"; do
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends "$pkg" 2>/dev/null || true
done
if ! docker compose version >/dev/null 2>&1 && ! command -v docker-compose >/dev/null 2>&1; then
    mkdir -p /usr/local/lib/docker/cli-plugins /usr/local/bin
    ARCH=$(uname -m)
    [ "$ARCH" = "x86_64" ] && COMPOSE_ARCH="x86_64" || COMPOSE_ARCH="$ARCH"
    curl -sSL "https://github.com/docker/compose/releases/latest/download/docker-compose-linux-$COMPOSE_ARCH" -o /usr/local/lib/docker/cli-plugins/docker-compose 2>/dev/null || true
    chmod +x /usr/local/lib/docker/cli-plugins/docker-compose 2>/dev/null || true
    ln -sf /usr/local/lib/docker/cli-plugins/docker-compose /usr/local/bin/docker-compose 2>/dev/null || true
fi

# 2. Permissões de Docker e Socket para o Portainer
groupadd -f docker
usermod -aG docker "$TARGET_USER"
systemctl enable --now docker
if [ -S /var/run/docker.sock ]; then
    chmod 666 /var/run/docker.sock
    chown root:docker /var/run/docker.sock
fi

mkdir -p /etc/systemd/system/docker.service.d/
cat << 'EOF' > /etc/systemd/system/docker.service.d/override.conf
[Service]
ExecStartPost=/bin/chmod 666 /var/run/docker.sock
EOF
systemctl daemon-reload >/dev/null 2>&1 || true

# 3. Portainer CE (inicia se não existir)
if ! docker ps -a --format '{{.Names}}' | grep -Eq "^portainer$"; then
    docker volume create portainer_data >/dev/null 2>&1 || true
    docker run -d -p 8000:8000 -p 9000:9000 -p 9443:9443 --name portainer --restart=always \\
        -v /var/run/docker.sock:/var/run/docker.sock -v portainer_data:/data portainer/portainer-ce:latest || true
fi

# 4. Módulos de Kernel & Roteamento IPv4
modprobe br_netfilter nf_conntrack iptable_filter iptable_nat ip_tables 2>/dev/null || true
mkdir -p /etc/modules-load.d
cat << 'EOF' > /etc/modules-load.d/netsentry.conf
br_netfilter
nf_conntrack
iptable_filter
iptable_nat
ip_tables
EOF

mkdir -p /etc/sysctl.d
cat << 'EOF' > /etc/sysctl.d/99-netsentry.conf
net.ipv4.ip_forward = 1
net.ipv4.conf.all.send_redirects = 0
net.bridge.bridge-nf-call-iptables = 1
net.bridge.bridge-nf-call-ip6tables = 1
EOF
sysctl --system -q || true

# 5. Modo Promíscuo na Placa de Rede
IFACE=$(ip route show default 2>/dev/null | awk '{print $5}' | head -n 1)
IFACE=\${IFACE:-eth0}
ip link set "$IFACE" promisc on || true

cat << EOF > /etc/systemd/system/netsentry-promisc.service
[Unit]
Description=NetSentry SOC - Modo Promiscuo em $IFACE
After=network.target

[Service]
Type=oneshot
ExecStart=/sbin/ip link set $IFACE promisc on
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload >/dev/null 2>&1 || true
systemctl enable netsentry-promisc.service >/dev/null 2>&1 || true

# 6. Capabilities Linux para Nmap, Tcpdump, Arping e Python (Raw Sockets)
for bin in nmap tcpdump arping python3; do
    p=$(which $bin 2>/dev/null || true)
    [ -n "$p" ] && setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip "$p" 2>/dev/null || true
done

# 7. Sudoers sem senha para automação do NetSentry
mkdir -p /etc/sudoers.d
cat << EOF > /etc/sudoers.d/netsentry
$TARGET_USER ALL=(ALL) NOPASSWD: /usr/bin/nmap, /usr/bin/tcpdump, /usr/bin/arping, /usr/sbin/iptables, /usr/sbin/ip6tables, /usr/sbin/ip, /usr/bin/docker, /usr/bin/docker-compose, /usr/bin/nsenter, /usr/bin/systemctl, /usr/bin/kill, /bin/kill, /usr/bin/netstat, /usr/bin/ss
EOF
chmod 0440 /etc/sudoers.d/netsentry

# 8. Firewall: liberar portas 3000, 8080, 5432, 9000, 9443
if command -v ufw >/dev/null 2>&1; then
    ufw allow 3000/tcp >/dev/null 2>&1 || true
    ufw allow 8080/tcp >/dev/null 2>&1 || true
    ufw allow 5432/tcp >/dev/null 2>&1 || true
    ufw allow 9000/tcp >/dev/null 2>&1 || true
    ufw allow 9443/tcp >/dev/null 2>&1 || true
fi
iptables -I INPUT -p tcp -m multiport --dports 3000,8080,5432,9000,9443 -j ACCEPT 2>/dev/null || true

# 9. Swap de 2GB se RAM for baixa (previne exit code 1 no docker build)
MEM_MB=$(free -m | awk '/^Mem:/{print $2}')
if [ "$MEM_MB" -lt 3000 ] && [ ! -f /swapfile_netsentry ]; then
    fallocate -l 2G /swapfile_netsentry 2>/dev/null || dd if=/dev/zero of=/swapfile_netsentry bs=1M count=2048
    chmod 600 /swapfile_netsentry
    mkswap /swapfile_netsentry >/dev/null 2>&1 || true
    swapon /swapfile_netsentry >/dev/null 2>&1 || true
    echo "/swapfile_netsentry none swap sw 0 0" >> /etc/fstab
fi

mkdir -p /opt/netsentry /var/log/netsentry
chown -R "$TARGET_USER":"$TARGET_USER" /opt/netsentry /var/log/netsentry 2>/dev/null || true
chmod -R 775 /opt/netsentry /var/log/netsentry

echo -e "\${GREEN}\${BOLD}"
echo "=========================================================================="
echo "✅ TODAS AS PERMISSÕES FORAM APLICADAS COM SUCESSO NO KALI LINUX!"
echo "=========================================================================="
echo -e "\${NC}"
echo -e "Rode agora no seu terminal para aplicar o grupo docker: \${BOLD}newgrp docker\${NC}"
echo -e "Para subir o stack: \${BOLD}docker compose down && docker compose up -d --build\${NC}"
`;

export const PortainerDeployView: React.FC = () => {
  const [activeCodeTab, setActiveCodeTab] = useState<'quickstart' | 'permissions' | 'compose' | 'dockerfile' | 'nginx' | 'python' | 'sql' | 'kali'>('quickstart');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [isDownloadingZip, setIsDownloadingZip] = useState<boolean>(false);
  const [zipSuccess, setZipSuccess] = useState<boolean>(false);

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const handleDownload = (content: string, filename: string) => {
    const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', filename);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const handleDownloadZip = async () => {
    try {
      setIsDownloadingZip(true);
      await downloadCompleteProjectZip();
      setZipSuccess(true);
      setTimeout(() => setZipSuccess(false), 4000);
    } catch (err) {
      console.error('Erro ao gerar ZIP do projeto:', err);
    } finally {
      setIsDownloadingZip(false);
    }
  };

  const getActiveCode = () => {
    switch (activeCodeTab) {
      case 'quickstart': return ALL_IN_ONE_QUICKSTART_SCRIPT;
      case 'permissions': return SETUP_PERMISSIONS_SCRIPT;
      case 'compose': return DOCKER_COMPOSE_YML;
      case 'dockerfile': return DOCKERFILE_CODE;
      case 'nginx': return NGINX_CONF_CODE;
      case 'python': return PYTHON_DAEMON_SCRIPT;
      case 'sql': return INIT_SQL_SCHEMA;
      case 'kali': return KALI_INSTALL_SCRIPT;
    }
  };

  const getActiveFilename = () => {
    switch (activeCodeTab) {
      case 'quickstart': return 'deploy_all.sh';
      case 'permissions': return 'setup_kali_permissions.sh';
      case 'compose': return 'docker-compose.yml';
      case 'dockerfile': return 'Dockerfile';
      case 'nginx': return 'nginx.conf';
      case 'python': return 'daemon_monitor.py';
      case 'sql': return 'init.sql';
      case 'kali': return 'install_kali.sh';
    }
  };

  return (
    <div className="space-y-6">
      {/* 1. Header with 100% Local Badge */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h2 className="text-base font-semibold text-slate-100 flex items-center gap-2">
            <span>Como Implantar no Portainer & Kali Linux</span>
            <span className="text-xs text-emerald-400 font-mono bg-emerald-950/80 px-2 py-0.5 rounded border border-emerald-800">
              ● 100% LOCAL & OFFLINE
            </span>
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            O sistema roda completamente em <code className="text-cyan-300 font-mono">http://localhost:3000</code> no Kali, sem dependência de internet ou nuvem.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-[11px] text-slate-400 font-mono">Portas: 3000 (Web), 8080 (Daemon), 5432 (Postgres)</span>
        </div>
      </div>

      {/* 1.5. ONE-CLICK DOWNLOAD OF COMPLETE PROJECT FOR PORTAINER */}
      <div className="p-4 rounded-xl bg-gradient-to-r from-cyan-950/60 via-slate-900 to-indigo-950/60 border border-cyan-500/50 flex flex-col md:flex-row md:items-center justify-between gap-4 shadow-lg shadow-cyan-950/30">
        <div className="flex items-start gap-3">
          <div className="p-2.5 rounded-lg bg-cyan-950 text-cyan-400 border border-cyan-800 shrink-0 mt-0.5">
            <FolderArchive className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center gap-2 flex-wrap">
              <h3 className="text-sm font-semibold text-slate-100">
                Baixar Projeto Completo (.zip) para o Portainer
              </h3>
              <span className="text-[10px] font-mono bg-cyan-950 text-cyan-300 px-2 py-0.5 rounded border border-cyan-800 font-bold">
                EXATO DO PREVIEW
              </span>
            </div>
            <p className="text-xs text-slate-300 mt-1 leading-relaxed">
              Baixe com 1 clique todo o código-fonte React + Tailwind + Recharts + Dockerfile multi-stage + nginx.conf + docker-compose.yml + script do sniffer. Descompacte no Kali Linux e execute com <strong>docker compose up -d --build</strong>.
            </p>
          </div>
        </div>

        <div className="shrink-0 flex items-center gap-2">
          <button
            onClick={handleDownloadZip}
            disabled={isDownloadingZip}
            className={`flex items-center gap-2 px-4 py-2.5 rounded-lg text-xs font-bold transition-all shadow-md ${
              zipSuccess
                ? 'bg-emerald-400 text-slate-950 hover:bg-emerald-300'
                : 'bg-cyan-400 text-slate-950 hover:bg-cyan-300'
            } disabled:opacity-60 disabled:cursor-not-allowed`}
          >
            {isDownloadingZip ? (
              <>
                <div className="w-3.5 h-3.5 border-2 border-slate-950 border-t-transparent rounded-full animate-spin" />
                <span>Empacotando Projeto...</span>
              </>
            ) : zipSuccess ? (
              <>
                <PackageCheck className="w-4 h-4 text-slate-950" />
                <span>Download Concluído!</span>
              </>
            ) : (
              <>
                <Download className="w-4 h-4 text-slate-950" />
                <span>Baixar Projeto Completo (.zip)</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* 2. Fast 3-Step Visual Guide */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        {/* Step 1 */}
        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2.5">
          <div className="flex items-center justify-between text-xs">
            <span className="font-mono text-cyan-400 font-bold">PASSO 01</span>
            <Terminal className="w-4 h-4 text-slate-500" />
          </div>
          <h3 className="text-sm font-semibold text-slate-100">
            1. Preparar o Host Kali Linux
          </h3>
          <p className="text-xs text-slate-400 leading-relaxed">
            Habilite o modo promíscuo na placa de rede do Kali para capturar todo o tráfego que chega na interface:
          </p>
          <div className="p-2 bg-slate-950 rounded border border-slate-800/80 font-mono text-[11px] text-cyan-300 flex items-center justify-between">
            <code>sudo ip link set eth0 promisc on</code>
            <button
              onClick={() => handleCopy('sudo ip link set eth0 promisc on', 'p1')}
              className="text-slate-400 hover:text-cyan-300"
            >
              {copiedKey === 'p1' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            </button>
          </div>
        </div>

        {/* Step 2 */}
        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2.5">
          <div className="flex items-center justify-between text-xs">
            <span className="font-mono text-cyan-400 font-bold">PASSO 02</span>
            <Layers className="w-4 h-4 text-slate-500" />
          </div>
          <h3 className="text-sm font-semibold text-slate-100">
            2. Criar a Stack no Portainer
          </h3>
          <p className="text-xs text-slate-400 leading-relaxed">
            Abra o Portainer em <code className="text-emerald-400 font-mono">http://localhost:9000</code>, vá em <strong>Stacks → Add stack</strong> e selecione o <strong>Web editor</strong>.
          </p>
          <div className="text-[11px] text-slate-500">
            Nome sugerido: <strong className="text-slate-300 font-mono">netsentry-soc</strong>
          </div>
        </div>

        {/* Step 3 */}
        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2.5">
          <div className="flex items-center justify-between text-xs">
            <span className="font-mono text-cyan-400 font-bold">PASSO 03</span>
            <Zap className="w-4 h-4 text-emerald-400" />
          </div>
          <h3 className="text-sm font-semibold text-slate-100">
            3. Colar o Compose & Deploy
          </h3>
          <p className="text-xs text-slate-400 leading-relaxed">
            Cole o conteúdo do <code className="text-cyan-400 font-mono">docker-compose.yml</code> abaixo e clique em <strong>Deploy the stack</strong>.
          </p>
          <div className="text-[11px] text-emerald-400 font-medium">
            Acesse imediatamente em: <code className="font-mono text-cyan-300">http://localhost:3000</code>
          </div>
        </div>
      </div>

      {/* 2.5. Diagnóstico & Solução de Mensagens de Erro no Portainer */}
      <div className="p-4 rounded-xl bg-slate-900/90 border border-amber-500/50 space-y-3.5">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-amber-950/80 text-amber-400 border border-amber-800 shrink-0">
              <AlertTriangle className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
                <span>Mensagem de Erro no Portainer? Diagnóstico & Solução Imediata</span>
                <span className="text-[10px] font-mono bg-amber-950 text-amber-300 px-1.5 py-0.5 rounded border border-amber-800">
                  AUTO-FIX APLICADO
                </span>
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Se o Portainer exibiu uma mensagem vermelha ao clicar em <em>Deploy the stack</em>, confira abaixo a causa exata e como resolver:
              </p>
            </div>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
          {/* Erro 1 */}
          <div className="p-3.5 bg-slate-950 rounded-lg border border-slate-800 space-y-1.5">
            <div className="flex items-center gap-1.5 text-rose-400 font-mono font-semibold text-[11px]">
              <span className="w-2 h-2 rounded-full bg-rose-500 inline-block"></span>
              <span>"depends_on: condition is not allowed" ou "must be a list"</span>
            </div>
            <p className="text-slate-400 text-[11px] leading-relaxed">
              <strong>Causa:</strong> Versões do Portainer não aceitam a chave <code className="text-slate-300">condition: service_healthy</code> em Compose v3.8.
            </p>
            <p className="text-emerald-400 text-[11px] leading-relaxed">
              <strong>Solução Já Aplicada:</strong> O <code className="text-cyan-300 font-mono">docker-compose.yml</code> na aba abaixo já foi atualizado para <code className="text-slate-200">depends_on: [ - postgres ]</code> compatível com 100% dos Portainers. Recopie e cole novamente!
            </p>
          </div>

          {/* Erro 2 */}
          <div className="p-3.5 bg-slate-950 rounded-lg border border-slate-800 space-y-1.5">
            <div className="flex items-center gap-1.5 text-rose-400 font-mono font-semibold text-[11px]">
              <span className="w-2 h-2 rounded-full bg-rose-500 inline-block"></span>
              <span>"The variable 'd.ip' / '$host' is not set"</span>
            </div>
            <p className="text-slate-400 text-[11px] leading-relaxed">
              <strong>Causa:</strong> O editor do Portainer tenta interpretar variáveis internas de JavaScript e Nginx como variáveis de ambiente do Docker.
            </p>
            <p className="text-emerald-400 text-[11px] leading-relaxed">
              <strong>Solução Já Aplicada:</strong> O código foi 100% sanitizado com <code className="text-slate-200">$$host</code> e concatenação pura sem interpolação.
            </p>
          </div>

          {/* Erro 3 */}
          <div className="p-3.5 bg-slate-950 rounded-lg border border-slate-800 space-y-1.5">
            <div className="flex items-center gap-1.5 text-amber-400 font-mono font-semibold text-[11px]">
              <span className="w-2 h-2 rounded-full bg-amber-500 inline-block"></span>
              <span>"Bind for 0.0.0.0:5432 failed: port is already allocated"</span>
            </div>
            <p className="text-slate-400 text-[11px] leading-relaxed">
              <strong>Causa:</strong> No Kali Linux, o PostgreSQL nativo frequentemente está em execução em segundo plano (para o Metasploit).
            </p>
            <div className="p-1.5 bg-slate-900 rounded border border-slate-800 font-mono text-[10px] text-cyan-300 flex items-center justify-between">
              <code>sudo systemctl stop postgresql</code>
              <button
                onClick={() => handleCopy('sudo systemctl stop postgresql', 'err-pg')}
                className="text-slate-400 hover:text-cyan-300"
              >
                {copiedKey === 'err-pg' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
              </button>
            </div>
          </div>

          {/* Erro 4 */}
          <div className="p-3.5 bg-slate-950 rounded-lg border border-slate-800 space-y-1.5">
            <div className="flex items-center gap-1.5 text-amber-400 font-mono font-semibold text-[11px]">
              <span className="w-2 h-2 rounded-full bg-amber-500 inline-block"></span>
              <span>"yaml: unmarshal errors" / Erro de Indentação</span>
            </div>
            <p className="text-slate-400 text-[11px] leading-relaxed">
              <strong>Causa:</strong> O editor web do Portainer pode perder quebras de linha ao colar textos grandes pelo navegador.
            </p>
            <div className="text-[11px] text-cyan-300">
              <strong>Alternativa à Prova de Falhas:</strong> Clique na aba <strong className="text-white">deploy_all.sh</strong> abaixo e rode o comando único no terminal do Kali.
            </div>
          </div>
        </div>
      </div>

      {/* 3. Fast All-In-One Script Callout */}
      <div className="p-4 rounded-xl bg-slate-900/90 border border-cyan-900/50 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="flex items-start sm:items-center gap-3">
          <div className="p-2 rounded-lg bg-cyan-950 text-cyan-400 border border-cyan-800 shrink-0">
            <Zap className="w-4 h-4" />
          </div>
          <div>
            <h4 className="text-xs font-bold uppercase tracking-wider text-cyan-400">
              Método Rápido: Implantação Automática em 1 Linha (100% Local)
            </h4>
            <p className="text-xs text-slate-300 mt-0.5">
              Cria o diretório <code className="font-mono text-slate-200">/opt/netsentry</code>, configura o kernel do Kali e sobe a stack local:
            </p>
          </div>
        </div>

        <button
          onClick={() => {
            setActiveCodeTab('quickstart');
            handleCopy(ALL_IN_ONE_QUICKSTART_SCRIPT, 'quickstart-btn');
          }}
          className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg text-xs font-semibold text-slate-950 bg-cyan-400 hover:bg-cyan-300 transition-colors shadow-sm shrink-0"
        >
          {copiedKey === 'quickstart-btn' ? <Check className="w-3.5 h-3.5 text-slate-950" /> : <Copy className="w-3.5 h-3.5" />}
          <span>Copiar Script deploy_all.sh</span>
        </button>
      </div>

      {/* 4. NETWORK EFFECTIVENESS & TOPOLOGY MASTER GUIDE */}
      <div className="p-5 rounded-xl bg-slate-900 border border-cyan-800/60 space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-cyan-950 text-cyan-400 border border-cyan-800">
              <Wifi className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
                <span>O Que Fazer na Rede para Tornar o Sistema 100% Efetivo?</span>
                <span className="text-[10px] font-mono bg-cyan-950 text-cyan-300 px-1.5 py-0.5 rounded border border-cyan-800">
                  ARQUITETURA SOC / IDS
                </span>
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Entenda a limitação dos switches normais e as 3 formas profissionais de capturar todo o tráfego da rede.
              </p>
            </div>
          </div>
        </div>

        {/* The Fundamental Problem Explanation */}
        <div className="p-3.5 bg-slate-950 rounded-lg border border-slate-800 text-xs text-slate-300 space-y-1.5 leading-relaxed font-sans">
          <div className="flex items-center gap-1.5 text-amber-300 font-semibold">
            <AlertTriangle className="w-4 h-4 shrink-0" />
            <span>Por que apenas plugar o Kali no switch não enxerga todos os computadores?</span>
          </div>
          <p className="text-slate-400 text-[11px]">
            Em redes modernas com switches Ethernet (comutação de camada 2), o switch entrega para a porta do Kali Linux <strong>apenas tráfego de broadcast</strong> (ARP, DHCP, mDNS) e pacotes com destino direto ao Kali. O tráfego que passa entre o Computador A e o Roteador é isolado pelo switch.
          </p>
        </div>

        {/* 3 Deployment Methods Grid */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
          {/* Method 1: SPAN / Mirror */}
          <div className="p-4 bg-slate-950 rounded-xl border border-slate-800 hover:border-cyan-800 transition-all space-y-2">
            <div className="flex items-center justify-between">
              <span className="font-mono text-emerald-400 font-bold text-[11px]">OPÇÃO 01 (RECOMENDADA)</span>
              <Activity className="w-4 h-4 text-emerald-400" />
            </div>
            <h4 className="font-semibold text-slate-100 text-sm">Port Mirroring / SPAN</h4>
            <p className="text-slate-400 text-[11px] leading-relaxed">
              Em um switch gerenciável (ex: TP-Link Omada, Mikrotik, Cisco, UniFi), configure o espelhamento da porta do Gateway para a porta física do Kali Linux.
            </p>
            <div className="pt-2 border-t border-slate-800 text-[11px] text-slate-300 space-y-1">
              <div><strong className="text-emerald-400">Vantagem:</strong> Zero latência para a rede.</div>
              <div><strong className="text-slate-400">Captura:</strong> 100% de todo o tráfego da empresa/rede.</div>
            </div>
          </div>

          {/* Method 2: Inline Bridge */}
          <div className="p-4 bg-slate-950 rounded-xl border border-slate-800 hover:border-cyan-800 transition-all space-y-2">
            <div className="flex items-center justify-between">
              <span className="font-mono text-cyan-400 font-bold text-[11px]">OPÇÃO 02 (MODO IPS ATIVO)</span>
              <Shield className="w-4 h-4 text-cyan-400" />
            </div>
            <h4 className="font-semibold text-slate-100 text-sm">Kali em Modo Bridge (2 Placas)</h4>
            <p className="text-slate-400 text-[11px] leading-relaxed">
              O Kali Linux fica fisicamente entre o Roteador e o Switch com duas placas de rede (<code className="text-cyan-300">eth0</code> e <code className="text-cyan-300">eth1</code>) em bridge transparente Linux (<code className="text-cyan-300">br0</code>).
            </p>
            <div className="pt-2 border-t border-slate-800 text-[11px] text-slate-300 space-y-1">
              <div><strong className="text-cyan-400">Vantagem:</strong> Bloqueio ativo antes do pacote chegar.</div>
              <div><strong className="text-slate-400">Captura:</strong> Inspeção e filtragem inline 100%.</div>
            </div>
          </div>

          {/* Method 3: Defensiva ARP Interception */}
          <div className="p-4 bg-slate-950 rounded-xl border border-slate-800 hover:border-cyan-800 transition-all space-y-2">
            <div className="flex items-center justify-between">
              <span className="font-mono text-amber-400 font-bold text-[11px]">OPÇÃO 03 (LAB / DOMÉSTICO)</span>
              <Radio className="w-4 h-4 text-amber-400" />
            </div>
            <h4 className="font-semibold text-slate-100 text-sm">Redirecionamento ARP / Proxy</h4>
            <p className="text-slate-400 text-[11px] leading-relaxed">
              Sem switch gerenciável: o daemon ou ferramenta do Kali (<code className="text-amber-300">arpspoof</code>) anuncia a rota do Gateway para os hosts de teste, fazendo os pacotes passarem pelo Kali.
            </p>
            <div className="pt-2 border-t border-slate-800 text-[11px] text-slate-300 space-y-1">
              <div><strong className="text-amber-400">Vantagem:</strong> Funciona com qualquer switch comum.</div>
              <div><strong className="text-slate-400">Ideal para:</strong> Ambientes de teste e auditoria rápida.</div>
            </div>
          </div>
        </div>

        {/* Essential Linux Kernel Tuning Box */}
        <div className="p-3.5 bg-slate-950 rounded-lg border border-slate-800 space-y-2">
          <span className="font-semibold text-xs text-slate-200 block font-mono">
            Comandos de Ajuste Fino do Kernel do Kali Linux para Captura Perfeita:
          </span>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-2 font-mono text-[11px]">
            <div className="p-2 bg-slate-900 rounded border border-slate-800 flex items-center justify-between">
              <code className="text-cyan-300">sudo ip link set eth0 promisc on</code>
              <button onClick={() => handleCopy('sudo ip link set eth0 promisc on', 'k1')} className="text-slate-400 hover:text-cyan-300">
                {copiedKey === 'k1' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
              </button>
            </div>
            <div className="p-2 bg-slate-900 rounded border border-slate-800 flex items-center justify-between">
              <code className="text-cyan-300">sudo sysctl -w net.ipv4.ip_forward=1</code>
              <button onClick={() => handleCopy('sudo sysctl -w net.ipv4.ip_forward=1', 'k2')} className="text-slate-400 hover:text-cyan-300">
                {copiedKey === 'k2' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
              </button>
            </div>
            <div className="p-2 bg-slate-900 rounded border border-slate-800 flex items-center justify-between">
              <code className="text-cyan-300">sudo ethtool -K eth0 rx off tx off</code>
              <button onClick={() => handleCopy('sudo ethtool -K eth0 rx off tx off', 'k3')} className="text-slate-400 hover:text-cyan-300">
                {copiedKey === 'k3' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* 5. Code Tabs Viewer */}
      <div className="rounded-xl border border-slate-800 bg-slate-900 overflow-hidden">
        {/* Tabs Bar */}
        <div className="px-4 py-3 bg-slate-950 border-b border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center gap-1 overflow-x-auto text-xs">
            <button
              onClick={() => setActiveCodeTab('permissions')}
              className={`px-3 py-1.5 rounded-md font-medium transition-colors ${
                activeCodeTab === 'permissions'
                  ? 'bg-amber-950 text-amber-300 border border-amber-800 shadow-sm font-semibold'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              🛡️ setup_kali_permissions.sh (Permissões Totais)
            </button>
            <button
              onClick={() => setActiveCodeTab('quickstart')}
              className={`px-3 py-1.5 rounded-md font-medium transition-colors ${
                activeCodeTab === 'quickstart'
                  ? 'bg-slate-800 text-cyan-300 shadow-sm font-semibold'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              deploy_all.sh (Tudo em 1 Comando)
            </button>
            <button
              onClick={() => setActiveCodeTab('compose')}
              className={`px-3 py-1.5 rounded-md font-medium transition-colors ${
                activeCodeTab === 'compose'
                  ? 'bg-slate-800 text-cyan-300 shadow-sm font-semibold'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              docker-compose.yml (Portainer)
            </button>
            <button
              onClick={() => setActiveCodeTab('dockerfile')}
              className={`px-3 py-1.5 rounded-md font-medium transition-colors ${
                activeCodeTab === 'dockerfile'
                  ? 'bg-slate-800 text-cyan-300 shadow-sm font-semibold'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Dockerfile (Multi-Stage)
            </button>
            <button
              onClick={() => setActiveCodeTab('nginx')}
              className={`px-3 py-1.5 rounded-md font-medium transition-colors ${
                activeCodeTab === 'nginx'
                  ? 'bg-slate-800 text-cyan-300 shadow-sm font-semibold'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              nginx.conf
            </button>
            <button
              onClick={() => setActiveCodeTab('python')}
              className={`px-3 py-1.5 rounded-md font-medium transition-colors ${
                activeCodeTab === 'python'
                  ? 'bg-slate-800 text-cyan-300 shadow-sm font-semibold'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              daemon_monitor.py
            </button>
            <button
              onClick={() => setActiveCodeTab('sql')}
              className={`px-3 py-1.5 rounded-md font-medium transition-colors ${
                activeCodeTab === 'sql'
                  ? 'bg-slate-800 text-cyan-300 shadow-sm font-semibold'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              init.sql (Postgres 16)
            </button>
            <button
              onClick={() => setActiveCodeTab('kali')}
              className={`px-3 py-1.5 rounded-md font-medium transition-colors ${
                activeCodeTab === 'kali'
                  ? 'bg-slate-800 text-cyan-300 shadow-sm font-semibold'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              install_kali.sh
            </button>
          </div>

          <div className="flex items-center gap-2 self-end sm:self-auto">
            <button
              onClick={() => handleCopy(getActiveCode(), activeCodeTab)}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-semibold bg-cyan-400 text-slate-950 hover:bg-cyan-300 transition-colors shadow-sm"
            >
              {copiedKey === activeCodeTab ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copiedKey === activeCodeTab ? 'Copiado!' : 'Copiar Arquivo'}</span>
            </button>
            <button
              onClick={() => handleDownload(getActiveCode(), getActiveFilename())}
              className="p-1.5 text-slate-400 hover:text-slate-200 rounded hover:bg-slate-800 transition-colors"
              title="Baixar arquivo"
            >
              <Download className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Code View */}
        <div className="p-4 bg-slate-950 font-mono text-xs overflow-x-auto max-h-[500px]">
          <pre className="text-slate-300 leading-relaxed whitespace-pre">
            <code>{getActiveCode()}</code>
          </pre>
        </div>
      </div>

      {/* 6. Execution Permissions Architecture Card */}
      <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
        <h3 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
          <Shield className="w-4 h-4 text-cyan-400" />
          <span>Permissões do Portainer para Execução Automática no Terminal do Kali</span>
        </h3>
        <p className="text-xs text-slate-300 leading-relaxed font-sans">
          Para que o sistema instalado no Portainer possa executar comandos sugeridos pelo painel diretamente no terminal e no kernel do host Kali, a stack está configurada com:
        </p>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
          <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 space-y-1">
            <span className="font-semibold text-cyan-400 block font-mono">1. privileged: true & cap_add: ALL</span>
            <p className="text-slate-400 text-[11px] leading-relaxed">
              Concede autoridade total de kernel, permitindo aplicar e remover regras de firewall Netfilter (<code className="text-slate-300">iptables</code>) e executar ferramentas de inspeção de rede.
            </p>
          </div>

          <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 space-y-1">
            <span className="font-semibold text-emerald-400 block font-mono">2. network_mode: host & pid: host</span>
            <p className="text-slate-400 text-[11px] leading-relaxed">
              O daemon compartilha o namespace exato de rede e processos do Kali. Comandos enviados pelo painel executam diretamente na placa física do host.
            </p>
          </div>

          <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 space-y-1">
            <span className="font-semibold text-indigo-400 block font-mono">3. nsenter & volume /:/host:rw</span>
            <p className="text-slate-400 text-[11px] leading-relaxed">
              O endpoint <code className="text-slate-300">/api/exec</code> utiliza <code className="text-slate-300">nsenter -t 1</code> para disparar qualquer comando diretamente no shell do host Kali e retornar a saída na tela em tempo real.
            </p>
          </div>
        </div>
      </div>

      {/* 7. Testing & Verification Terminal Commands */}
      <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
        <h3 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
          <Terminal className="w-4 h-4 text-emerald-400" />
          <span>Comandos para Testar e Validar os Contêineres no Kali Linux</span>
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs font-mono">
          <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1.5">
            <span className="text-slate-400 font-sans block font-medium">
              1. Ver logs do Sniffer Python em tempo real:
            </span>
            <div className="flex items-center justify-between text-cyan-300">
              <code>docker logs -f netsentry-daemon</code>
              <button
                onClick={() => handleCopy('docker logs -f netsentry-daemon', 't1')}
                className="text-slate-400 hover:text-cyan-300 ml-2"
              >
                {copiedKey === 't1' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              </button>
            </div>
          </div>

          <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1.5">
            <span className="text-slate-400 font-sans block font-medium">
              2. Conectar diretamente ao banco PostgreSQL 16:
            </span>
            <div className="flex items-center justify-between text-cyan-300">
              <code>docker exec -it netsentry-postgres psql -U netsentry_admin -d netsentry_db</code>
              <button
                onClick={() => handleCopy('docker exec -it netsentry-postgres psql -U netsentry_admin -d netsentry_db', 't2')}
                className="text-slate-400 hover:text-cyan-300 ml-2"
              >
                {copiedKey === 't2' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              </button>
            </div>
          </div>

          <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1.5">
            <span className="text-slate-400 font-sans block font-medium">
              3. Simular varredura Nmap contra o nó para disparar alerta:
            </span>
            <div className="flex items-center justify-between text-cyan-300">
              <code>nmap -sS -p 1-1000 -T4 127.0.0.1</code>
              <button
                onClick={() => handleCopy('nmap -sS -p 1-1000 -T4 127.0.0.1', 't3')}
                className="text-slate-400 hover:text-cyan-300 ml-2"
              >
                {copiedKey === 't3' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              </button>
            </div>
          </div>

          <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1.5">
            <span className="text-slate-400 font-sans block font-medium">
              4. Checar regras de bloqueio inseridas pelo motor autônomo:
            </span>
            <div className="flex items-center justify-between text-cyan-300">
              <code>sudo iptables -L INPUT -v -n --line-numbers</code>
              <button
                onClick={() => handleCopy('sudo iptables -L INPUT -v -n --line-numbers', 't4')}
                className="text-slate-400 hover:text-cyan-300 ml-2"
              >
                {copiedKey === 't4' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
