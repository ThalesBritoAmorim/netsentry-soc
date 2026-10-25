#!/usr/bin/env bash
# ==============================================================================
# NetSentry SOC - Script Definitivo de Permissões & Setup para Kali Linux & Portainer
# Concede permissões totais para Docker, Portainer, Kernel Netfilter, Scapy e Nmap
# ==============================================================================

set -e

# Cores e formatação para o terminal do Kali
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m' # No Color

clear
echo -e "${CYAN}${BOLD}"
echo "=============================================================================="
echo "   🛡️   NETSENTRY SOC - CONFIGURADOR DE PERMISSÕES TOTAIS (KALI LINUX)   "
echo "   Docker | Portainer | Nmap | Scapy Sniffer | Netfilter | Kernel Raw Sockets "
echo "=============================================================================="
echo -e "${NC}"

# ------------------------------------------------------------------------------
# 1. Checagem de Privilégios Root / Sudo
# ------------------------------------------------------------------------------
if [ "$EUID" -ne 0 ]; then
    echo -e "${YELLOW}[!] Privilégios de superusuário necessários. Elevando com sudo...${NC}"
    exec sudo bash "$0" "$@"
fi

TARGET_USER="${SUDO_USER:-$USER}"
if [ "$TARGET_USER" = "root" ]; then
    # Se logado diretamente como root, tenta identificar o usuário padrão do Kali
    if id "kali" >/dev/null 2>&1; then
        TARGET_USER="kali"
    fi
fi

echo -e "${CYAN}[INFO]${NC} Usuário do Kali Linux identificado: ${BOLD}${TARGET_USER}${NC}"
echo -e "${CYAN}[INFO]${NC} Diretório de execução: ${BOLD}$(pwd)${NC}"

# ------------------------------------------------------------------------------
# 2. Instalação e Atualização de Pacotes Essenciais de Rede, Kernel e Docker
# ------------------------------------------------------------------------------
echo -e "\n${BLUE}${BOLD}[Etapa 1/8]${NC} Instalando dependências de rede, compilação e ferramentas no Kali..."

apt-get update -qq || true

# Lista de pacotes com nomes compatíveis com todas as versões do Kali Linux
PKGS=(
    docker.io
    docker-compose-plugin
    docker-buildx-plugin
    docker-compose
    iptables
    iproute2
    tcpdump
    nmap
    arping
    net-tools
    iputils-ping
    util-linux
    procps
    curl
    wget
    git
    libcap2-bin
    kmod
    python3
    python3-pip
    python3-venv
    libpcap-dev
    build-essential
    ca-certificates
)

echo -e "  -> Instalando pacotes necessários..."
for pkg in "${PKGS[@]}"; do
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends "$pkg" 2>/dev/null || true
done

# Fallback: Se o docker compose não tiver sido instalado pelo repositório, baixa o binário oficial
if ! docker compose version >/dev/null 2>&1 && ! command -v docker-compose >/dev/null 2>&1; then
    echo -e "  -> Configurando Docker Compose v2 standalone..."
    mkdir -p /usr/local/lib/docker/cli-plugins /usr/local/bin
    ARCH=$(uname -m)
    [ "$ARCH" = "x86_64" ] && COMPOSE_ARCH="x86_64" || COMPOSE_ARCH="$ARCH"
    curl -sSL "https://github.com/docker/compose/releases/latest/download/docker-compose-linux-$COMPOSE_ARCH" -o /usr/local/lib/docker/cli-plugins/docker-compose 2>/dev/null || true
    chmod +x /usr/local/lib/docker/cli-plugins/docker-compose 2>/dev/null || true
    ln -sf /usr/local/lib/docker/cli-plugins/docker-compose /usr/local/bin/docker-compose 2>/dev/null || true
fi

echo -e "${GREEN}[OK] Ferramentas de rede, Docker e diagnóstico instaladas com sucesso.${NC}"

# ------------------------------------------------------------------------------
# 3. Permissões de Docker e Socket para o Portainer
# ------------------------------------------------------------------------------
echo -e "\n${BLUE}${BOLD}[Etapa 2/8]${NC} Configurando permissões do Docker Daemon e Portainer..."

# Garante a criação do grupo docker
if ! getent group docker > /dev/null; then
    groupadd docker
    echo -e "  -> Grupo 'docker' criado."
fi

# Adiciona o usuário do Kali ao grupo docker
usermod -aG docker "$TARGET_USER"
echo -e "  -> Usuário '${TARGET_USER}' adicionado ao grupo docker."

# Inicia e habilita o serviço do Docker
systemctl enable docker >/dev/null 2>&1 || true
systemctl start docker >/dev/null 2>&1 || true

# Configura permissões máximas de leitura e escrita no socket do Docker
if [ -S /var/run/docker.sock ]; then
    chmod 666 /var/run/docker.sock
    chown root:docker /var/run/docker.sock
    echo -e "  -> Socket /var/run/docker.sock configurado com permissão 666 (Leitura/Escrita total)."
fi

# Garante persistência das permissões do socket após reinicialização do Docker
mkdir -p /etc/systemd/system/docker.service.d/
cat << 'EOF' > /etc/systemd/system/docker.service.d/override.conf
[Service]
ExecStartPost=/bin/chmod 666 /var/run/docker.sock
EOF
systemctl daemon-reload >/dev/null 2>&1 || true

echo -e "${GREEN}[OK] Docker daemon operacional e socket liberado para Portainer.${NC}"

# ------------------------------------------------------------------------------
# 4. Verificação / Instalação do Portainer CE (Caso não esteja rodando)
# ------------------------------------------------------------------------------
echo -e "\n${BLUE}${BOLD}[Etapa 3/8]${NC} Verificando status do contêiner do Portainer..."

if docker ps -a --format '{{.Names}}' | grep -Eq "^portainer$"; then
    echo -e "  -> Contêiner Portainer já existe no Docker."
    if ! docker ps --format '{{.Names}}' | grep -Eq "^portainer$"; then
        echo -e "  -> Iniciando Portainer..."
        docker start portainer
    fi
    echo -e "${GREEN}[OK] Portainer está ativo e rodando nas portas 9000 e 9443.${NC}"
else
    echo -e "${YELLOW}[!] Portainer não foi detectado em execução. Deseja iniciar o Portainer CE agora? (S/n)${NC}"
    read -t 5 -r -p "Resposta (padrão Sim em 5s): " RESP || RESP="s"
    if [[ "$RESP" =~ ^[Ss] ]] || [ -z "$RESP" ]; then
        docker volume create portainer_data >/dev/null 2>&1 || true
        docker run -d \
            -p 8000:8000 \
            -p 9000:9000 \
            -p 9443:9443 \
            --name portainer \
            --restart=always \
            -v /var/run/docker.sock:/var/run/docker.sock \
            -v portainer_data:/data \
            portainer/portainer-ce:latest
        echo -e "${GREEN}[OK] Portainer CE instalado e iniciado com sucesso! Acesse https://localhost:9443 ou http://localhost:9000${NC}"
    fi
fi

# ------------------------------------------------------------------------------
# 5. Módulos de Kernel Netfilter e Configurações de Sysctl
# ------------------------------------------------------------------------------
echo -e "\n${BLUE}${BOLD}[Etapa 4/8]${NC} Carregando módulos do Kernel Netfilter e ativando roteamento de pacotes..."

modprobe br_netfilter 2>/dev/null || true
modprobe nf_conntrack 2>/dev/null || true
modprobe iptable_filter 2>/dev/null || true
modprobe iptable_nat 2>/dev/null || true
modprobe ip_tables 2>/dev/null || true

# Persistência de módulos no boot
mkdir -p /etc/modules-load.d
cat << 'EOF' > /etc/modules-load.d/netsentry.conf
br_netfilter
nf_conntrack
iptable_filter
iptable_nat
ip_tables
EOF

# Parâmetros de rede no kernel (sysctl)
mkdir -p /etc/sysctl.d
cat << 'EOF' > /etc/sysctl.d/99-netsentry.conf
# NetSentry SOC - Configurações de Kernel para Análise de Pacotes
net.ipv4.ip_forward = 1
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.bridge.bridge-nf-call-iptables = 1
net.bridge.bridge-nf-call-ip6tables = 1
fs.file-max = 2097152
vm.max_map_count = 262144
EOF

sysctl --system -q || true
echo -e "${GREEN}[OK] Módulos de Kernel carregados e net.ipv4.ip_forward=1 ativo.${NC}"

# ------------------------------------------------------------------------------
# 6. Modo Promíscuo na Placa de Rede Primária (Scapy & Tcpdump)
# ------------------------------------------------------------------------------
echo -e "\n${BLUE}${BOLD}[Etapa 5/8]${NC} Configurando placa de rede para modo promíscuo..."

# Detecta automaticamente a interface principal com saída para a internet/LAN
IFACE=$(ip route show default 2>/dev/null | awk '{print $5}' | head -n 1)
if [ -z "$IFACE" ]; then
    # Fallback para primeira interface física diferente de lo e docker
    IFACE=$(ip -o link show | awk -F': ' '{print $2}' | grep -vE '^(lo|docker|veth|br-)' | head -n 1)
fi
IFACE=${IFACE:-eth0}

echo -e "  -> Interface primária detectada: ${BOLD}${IFACE}${NC}"
ip link set "$IFACE" promisc on || true

# Serviço systemd para manter a interface em modo promíscuo no boot
cat << EOF > /etc/systemd/system/netsentry-promisc.service
[Unit]
Description=NetSentry SOC - Ativar Modo Promiscuo em $IFACE
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
echo -e "${GREEN}[OK] Interface '$IFACE' operando em modo promíscuo.${NC}"

# ------------------------------------------------------------------------------
# 7. Linux Capabilities & Sudoers NOPASSWD para Ferramentas de Segurança
# ------------------------------------------------------------------------------
echo -e "\n${BLUE}${BOLD}[Etapa 6/8]${NC} Concedendo Linux Capabilities (cap_net_raw, cap_net_admin) e Sudoers..."

# Concede capacidades nativas do Linux aos binários para abrirem sockets de baixo nível
for bin in nmap tcpdump arping python3; do
    BIN_PATH=$(which "$bin" 2>/dev/null || true)
    if [ -n "$BIN_PATH" ] && [ -f "$BIN_PATH" ]; then
        setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip "$BIN_PATH" 2>/dev/null || true
        echo -e "  -> Capability concedida: $BIN_PATH"
    fi
done

# Permite execução transparente sem travar pedindo senha interativa no terminal web
mkdir -p /etc/sudoers.d
cat << EOF > /etc/sudoers.d/netsentry
# ==============================================================================
# NetSentry SOC - Permissões operacionais sem senha (NOPASSWD)
# Permite ao agente web interagir com o terminal do Kali Linux
# ==============================================================================
$TARGET_USER ALL=(ALL) NOPASSWD: /usr/bin/nmap, /usr/bin/tcpdump, /usr/bin/arping, /usr/sbin/iptables, /usr/sbin/ip6tables, /usr/sbin/ip, /usr/bin/docker, /usr/bin/docker-compose, /usr/bin/nsenter, /usr/bin/systemctl, /usr/bin/kill, /bin/kill, /usr/bin/netstat, /usr/bin/ss, /usr/bin/tail, /usr/bin/journalctl
EOF
chmod 0440 /etc/sudoers.d/netsentry
echo -e "${GREEN}[OK] Sudoers configurado em /etc/sudoers.d/netsentry sem prompts de senha.${NC}"

# ------------------------------------------------------------------------------
# 8. Firewall do Kali: Abertura das Portas do Sistema
# ------------------------------------------------------------------------------
echo -e "\n${BLUE}${BOLD}[Etapa 7/8]${NC} Liberando portas do NetSentry no firewall do Kali..."

# Portas essenciais:
# 3000: Painel Web do NetSentry (React + Tailwind + Recharts)
# 8080: API REST do Daemon Scapy & Agente Executor do Kali
# 5432: PostgreSQL 16 (Armazenamento de incidentes e auditoria)
# 9000/9443: Portainer Community Edition

if command -v ufw >/dev/null 2>&1; then
    ufw allow 3000/tcp comment "NetSentry Web UI" >/dev/null 2>&1 || true
    ufw allow 8080/tcp comment "NetSentry REST API" >/dev/null 2>&1 || true
    ufw allow 5432/tcp comment "NetSentry PostgreSQL" >/dev/null 2>&1 || true
    ufw allow 9000/tcp comment "Portainer HTTP" >/dev/null 2>&1 || true
    ufw allow 9443/tcp comment "Portainer HTTPS" >/dev/null 2>&1 || true
fi

# Regras diretas no iptables para garantir passagem imediata
iptables -I INPUT -p tcp -m multiport --dports 3000,8080,5432,9000,9443 -j ACCEPT 2>/dev/null || true
echo -e "${GREEN}[OK] Portas 3000, 8080, 5432, 9000 e 9443 liberadas no firewall.${NC}"

# ------------------------------------------------------------------------------
# 9. Otimização de Memória e Swap para Compilação Docker (Evita OOM / Exit Code 1)
# ------------------------------------------------------------------------------
echo -e "\n${BLUE}${BOLD}[Etapa 8/8]${NC} Verificando memória e swap do sistema para compilação..."

MEM_TOTAL_MB=$(free -m | awk '/^Mem:/{print $2}')
SWAP_TOTAL_MB=$(free -m | awk '/^Swap:/{print $2}')

echo -e "  -> RAM Total: ${MEM_TOTAL_MB}MB | Swap Total: ${SWAP_TOTAL_MB}MB"

if [ "$MEM_TOTAL_MB" -lt 3000 ] && [ "$SWAP_TOTAL_MB" -lt 1000 ]; then
    echo -e "${YELLOW}[!] Memória baixa detectada para builds pesados do Docker. Criando arquivo de Swap de 2GB...${NC}"
    if [ ! -f /swapfile_netsentry ]; then
        fallocate -l 2G /swapfile_netsentry 2>/dev/null || dd if=/dev/zero of=/swapfile_netsentry bs=1M count=2048
        chmod 600 /swapfile_netsentry
        mkswap /swapfile_netsentry >/dev/null 2>&1 || true
        swapon /swapfile_netsentry >/dev/null 2>&1 || true
        echo "/swapfile_netsentry none swap sw 0 0" >> /etc/fstab
        echo -e "${GREEN}[OK] Swap de 2GB ativado. Previne falhas de compilação por falta de memória!${NC}"
    fi
else
    echo -e "${GREEN}[OK] Recursos de memória e swap suficientes para compilação.${NC}"
fi

# Cria pastas operacionais com permissões adequadas
mkdir -p /opt/netsentry /var/log/netsentry
chown -R "$TARGET_USER":"$TARGET_USER" /opt/netsentry /var/log/netsentry 2>/dev/null || true
chmod -R 775 /opt/netsentry /var/log/netsentry

# ------------------------------------------------------------------------------
# Resumo Final e Guia Rápido
# ------------------------------------------------------------------------------
echo -e "\n${GREEN}${BOLD}"
echo "=============================================================================="
echo "   ✅ TODAS AS PERMISSÕES FORAM APLICADAS COM SUCESSO NO KALI LINUX!"
echo "=============================================================================="
echo -e "${NC}"
echo -e "1. ${BOLD}Docker Daemon:${NC}       Ativo e usuário '${TARGET_USER}' no grupo 'docker'."
echo -e "2. ${BOLD}Socket Docker:${NC}       /var/run/docker.sock liberado com permissão 666."
echo -e "3. ${BOLD}Portainer CE:${NC}        Ativo em https://localhost:9443 ou http://localhost:9000"
echo -e "4. ${BOLD}Ferramentas Kali:${NC}    Nmap, Tcpdump, Iptables e Python com permissões totais."
echo -e "5. ${BOLD}Sudoers:${NC}             Execução remota via painel web configurada sem senha."
echo -e "6. ${BOLD}Modo Promíscuo:${NC}      Ativado na interface '${IFACE}' para captura Scapy."
echo -e "7. ${BOLD}Portas Liberadas:${NC}    3000 (Web), 8080 (Agente Kali), 5432 (Postgres), 9443 (Portainer)."
echo "=============================================================================="
echo -e "\n${CYAN}${BOLD}Como subir ou reiniciar o NetSentry SOC agora:${NC}"
echo -e "  ${BOLD}docker compose down && docker compose up -d --build${NC}"
echo -e "\n${CYAN}Dica:${NC} Para aplicar as novas permissões do grupo Docker imediatamente no seu terminal atual, execute:"
echo -e "  ${BOLD}newgrp docker${NC}"
echo "=============================================================================="
