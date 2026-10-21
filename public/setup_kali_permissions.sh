#!/usr/bin/env bash
# ==============================================================================
# NetSentry SOC - Script Definitivo de Permissões & Setup para Kali Linux & Portainer
# Concede permissões totais para Docker, Portainer, Kernel Netfilter, Scapy e Nmap
# ==============================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m'

clear
echo -e "${CYAN}${BOLD}"
echo "=============================================================================="
echo "   🛡️   NETSENTRY SOC - CONFIGURADOR DE PERMISSÕES TOTAIS (KALI LINUX)   "
echo "   Docker | Portainer | Nmap | Scapy Sniffer | Netfilter | Kernel Raw Sockets "
echo "=============================================================================="
echo -e "${NC}"

if [ "$EUID" -ne 0 ]; then
    echo -e "${YELLOW}[!] Privilégios de superusuário necessários. Elevando com sudo...${NC}"
    exec sudo bash "$0" "$@"
fi

TARGET_USER="${SUDO_USER:-$USER}"
if [ "$TARGET_USER" = "root" ]; then
    if id "kali" >/dev/null 2>&1; then
        TARGET_USER="kali"
    fi
fi

echo -e "${CYAN}[INFO]${NC} Usuário do Kali Linux: ${BOLD}${TARGET_USER}${NC}"
echo -e "${CYAN}[INFO]${NC} Diretório de execução: ${BOLD}$(pwd)${NC}"

echo -e "\n${BLUE}${BOLD}[Etapa 1/8]${NC} Instalando dependências de rede, compilação e ferramentas no Kali..."
apt-get update -qq || true
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
    docker.io \
    docker-compose-v2 \
    iptables \
    iproute2 \
    tcpdump \
    nmap \
    arping \
    net-tools \
    iputils-ping \
    util-linux \
    procps \
    curl \
    wget \
    git \
    libcap2-bin \
    kmod \
    python3 \
    python3-pip \
    python3-venv \
    libpcap-dev \
    build-essential \
    ca-certificates

echo -e "${GREEN}[OK] Ferramentas instaladas.${NC}"

echo -e "\n${BLUE}${BOLD}[Etapa 2/8]${NC} Configurando permissões do Docker Daemon e Portainer..."
if ! getent group docker > /dev/null; then
    groupadd docker
fi
usermod -aG docker "$TARGET_USER"
systemctl enable docker >/dev/null 2>&1 || true
systemctl start docker >/dev/null 2>&1 || true

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
echo -e "${GREEN}[OK] Docker daemon operacional e socket liberado (chmod 666).${NC}"

echo -e "\n${BLUE}${BOLD}[Etapa 3/8]${NC} Verificando Portainer CE..."
if docker ps -a --format '{{.Names}}' | grep -Eq "^portainer$"; then
    if ! docker ps --format '{{.Names}}' | grep -Eq "^portainer$"; then
        docker start portainer
    fi
    echo -e "${GREEN}[OK] Portainer está ativo nas portas 9000 e 9443.${NC}"
else
    docker volume create portainer_data >/dev/null 2>&1 || true
    docker run -d \
        -p 8000:8000 \
        -p 9000:9000 \
        -p 9443:9443 \
        --name portainer \
        --restart=always \
        -v /var/run/docker.sock:/var/run/docker.sock \
        -v portainer_data:/data \
        portainer/portainer-ce:latest || true
    echo -e "${GREEN}[OK] Portainer CE iniciado nas portas 9000 e 9443.${NC}"
fi

echo -e "\n${BLUE}${BOLD}[Etapa 4/8]${NC} Carregando módulos do Kernel Netfilter..."
modprobe br_netfilter 2>/dev/null || true
modprobe nf_conntrack 2>/dev/null || true
modprobe iptable_filter 2>/dev/null || true
modprobe iptable_nat 2>/dev/null || true
modprobe ip_tables 2>/dev/null || true

cat << 'EOF' > /etc/modules-load.d/netsentry.conf
br_netfilter
nf_conntrack
iptable_filter
iptable_nat
ip_tables
EOF

cat << 'EOF' > /etc/sysctl.d/99-netsentry.conf
net.ipv4.ip_forward = 1
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.bridge.bridge-nf-call-iptables = 1
net.bridge.bridge-nf-call-ip6tables = 1
EOF
sysctl --system -q || true
echo -e "${GREEN}[OK] Netfilter e ip_forward configurados.${NC}"

echo -e "\n${BLUE}${BOLD}[Etapa 5/8]${NC} Configurando placa de rede em modo promíscuo..."
IFACE=$(ip route show default 2>/dev/null | awk '{print $5}' | head -n 1)
IFACE=${IFACE:-eth0}
ip link set "$IFACE" promisc on || true

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
echo -e "${GREEN}[OK] Interface '$IFACE' em modo promíscuo.${NC}"

echo -e "\n${BLUE}${BOLD}[Etapa 6/8]${NC} Concedendo Linux Capabilities e Sudoers NOPASSWD..."
for bin in nmap tcpdump arping python3; do
    BIN_PATH=$(which "$bin" 2>/dev/null || true)
    if [ -n "$BIN_PATH" ] && [ -f "$BIN_PATH" ]; then
        setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip "$BIN_PATH" 2>/dev/null || true
    fi
done

cat << EOF > /etc/sudoers.d/netsentry
$TARGET_USER ALL=(ALL) NOPASSWD: /usr/bin/nmap, /usr/bin/tcpdump, /usr/bin/arping, /usr/sbin/iptables, /usr/sbin/ip6tables, /usr/sbin/ip, /usr/bin/docker, /usr/bin/docker-compose, /usr/bin/nsenter, /usr/bin/systemctl, /usr/bin/kill, /bin/kill, /usr/bin/netstat, /usr/bin/ss
EOF
chmod 0440 /etc/sudoers.d/netsentry
echo -e "${GREEN}[OK] Capabilities e Sudoers configurados sem senha.${NC}"

echo -e "\n${BLUE}${BOLD}[Etapa 7/8]${NC} Liberando portas 3000, 8080, 5432, 9000, 9443 no firewall..."
if command -v ufw >/dev/null 2>&1; then
    ufw allow 3000/tcp >/dev/null 2>&1 || true
    ufw allow 8080/tcp >/dev/null 2>&1 || true
    ufw allow 5432/tcp >/dev/null 2>&1 || true
    ufw allow 9000/tcp >/dev/null 2>&1 || true
    ufw allow 9443/tcp >/dev/null 2>&1 || true
fi
iptables -I INPUT -p tcp -m multiport --dports 3000,8080,5432,9000,9443 -j ACCEPT 2>/dev/null || true
echo -e "${GREEN}[OK] Portas liberadas.${NC}"

echo -e "\n${BLUE}${BOLD}[Etapa 8/8]${NC} Verificando Swap e Memória..."
MEM_TOTAL_MB=$(free -m | awk '/^Mem:/{print $2}')
SWAP_TOTAL_MB=$(free -m | awk '/^Swap:/{print $2}')
if [ "$MEM_TOTAL_MB" -lt 3000 ] && [ "$SWAP_TOTAL_MB" -lt 1000 ]; then
    if [ ! -f /swapfile_netsentry ]; then
        fallocate -l 2G /swapfile_netsentry 2>/dev/null || dd if=/dev/zero of=/swapfile_netsentry bs=1M count=2048
        chmod 600 /swapfile_netsentry
        mkswap /swapfile_netsentry >/dev/null 2>&1 || true
        swapon /swapfile_netsentry >/dev/null 2>&1 || true
        echo "/swapfile_netsentry none swap sw 0 0" >> /etc/fstab
    fi
fi
mkdir -p /opt/netsentry /var/log/netsentry
chown -R "$TARGET_USER":"$TARGET_USER" /opt/netsentry /var/log/netsentry 2>/dev/null || true
chmod -R 775 /opt/netsentry /var/log/netsentry

echo -e "\n${GREEN}${BOLD}"
echo "=============================================================================="
echo "   ✅ TODAS AS PERMISSÕES FORAM APLICADAS COM SUCESSO NO KALI LINUX!"
echo "=============================================================================="
echo -e "${NC}"
echo -e "Para aplicar o grupo Docker imediatamente no seu terminal, rode:"
echo -e "  ${BOLD}newgrp docker${NC}"
