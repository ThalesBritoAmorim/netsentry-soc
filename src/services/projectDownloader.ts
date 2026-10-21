import JSZip from 'jszip';

// Vite importa todo o código-fonte como strings brutas usando ?raw
const sourceFiles = import.meta.glob([
  '/src/**/*.{ts,tsx,css}',
  '/index.html',
  '/package.json',
  '/vite.config.ts',
  '/tsconfig.json',
  '/Dockerfile',
  '/nginx.conf',
  '/setup_kali_permissions.sh',
  '/daemon_monitor.py'
], { query: '?raw', import: 'default', eager: true }) as Record<string, string>;

// Arquivos adicionais de infraestrutura para o Portainer / Kali Linux
const DOCKER_COMPOSE_CONTENT = `version: '3.8'

# ==============================================================================
# NetSentry SOC - Stack Completa para Portainer & Kali Linux
# Inclui: PostgreSQL 16 + Sniffer Scapy/Agente Kali + Frontend React Produção
# ==============================================================================

services:
  # 1. Banco de Dados Relacional PostgreSQL 16
  postgres:
    image: postgres:16-alpine
    container_name: netsentry-postgres
    restart: unless-stopped
    environment:
      POSTGRES_DB: netsentry_db
      POSTGRES_USER: netsentry_admin
      POSTGRES_PASSWORD: SecOps_Kali_2026!Strong
      PGDATA: /var/lib/postgresql/data/pgdata
    volumes:
      - postgres_data:/var/lib/postgresql/data
    ports:
      - "5432:5432"
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U netsentry_admin -d netsentry_db"]
      interval: 10s
      timeout: 5s
      retries: 5

  # 2. Daemon Python Autônomo com API REST (Sniffer Scapy + Agente Executor Kali)
  daemon:
    image: python:3.12-slim-bookworm
    container_name: netsentry-daemon
    restart: unless-stopped
    network_mode: host
    pid: host
    privileged: true
    cap_add:
      - ALL
    volumes:
      - /:/host:rw
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - /dev:/dev
      - /run:/run
    environment:
      - SNIFF_INTERFACE=eth0
      - API_PORT=8080
      - DB_HOST=127.0.0.1
      - DB_PORT=5432
      - DB_NAME=netsentry_db
      - DB_USER=netsentry_admin
      - DB_PASSWORD=SecOps_Kali_2026!Strong
      - AUTONOMOUS_MITIGATION=true
    entrypoint:
      - /bin/bash
      - -c
      - |
        apt-get update -qq && apt-get install -y -qq --no-install-recommends libpcap-dev gcc iptables iproute2 tcpdump arping nmap net-tools iputils-ping util-linux procps sudo curl
        pip install -q --no-cache-dir scapy psycopg2-binary
        python3 -u /daemon.py
    depends_on:
      - postgres

  # 3. Interface Web Completa (Exata do Preview do AI Studio com Nginx)
  web-ui:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: netsentry-web
    restart: unless-stopped
    network_mode: host
    ports:
      - "3000:3000"
    depends_on:
      - daemon

volumes:
  postgres_data:
`;

const DEPLOY_SCRIPT_CONTENT = `#!/usr/bin/env bash
# ==============================================================================
# NetSentry Kali SOC - Script de Instalação e Deploy Automático
# ==============================================================================
set -e

echo "=== [NetSentry] 1. Verificando pré-requisitos no Kali Linux ==="
if ! command -v docker &> /dev/null; then
    echo "Docker não encontrado. Instalando docker.io e docker-compose..."
    sudo apt-get update
    sudo apt-get install -y docker.io docker-compose-v2
    sudo systemctl enable --now docker
fi

echo "=== [NetSentry] 2. Configurando placa de rede no Kali em modo promíscuo ==="
IFACE=$(ip route | grep '^default' | awk '{print $5}' | head -n 1)
IFACE=\${IFACE:-eth0}
echo "Interface primária detectada: $IFACE"
sudo ip link set "$IFACE" promisc on || true

echo "=== [NetSentry] 3. Construindo e subindo os contêineres da Stack no Docker/Portainer ==="
docker compose up -d --build

echo ""
echo "=========================================================================="
echo "  NetSentry SOC IMPLANTADO COM SUCESSO!"
echo "  Acesse o Painel Web: http://localhost:3000"
echo "  API REST do Agente:   http://localhost:8080/api/status"
echo "  PostgreSQL 16:        localhost:5432 (banco: netsentry_db)"
echo "=========================================================================="
`;

const README_CONTENT = `# NetSentry SOC - Kali Linux & Portainer Stack

Projeto idêntico ao preview do Google AI Studio, pronto para rodar 100% local e offline no Kali Linux via Portainer ou Docker Compose.

## Como Executar no Kali Linux

### Método 1: Linha de Comando (Recomendado)
\`\`\`bash
# 1. Descompacte o arquivo zip
unzip netsentry-kali-soc.zip
cd netsentry-kali-soc

# 2. Dê permissão e execute o instalador
chmod +x deploy_all.sh
./deploy_all.sh
\`\`\`

### Método 2: Via Interface Web do Portainer
1. No Portainer, vá em **Stacks** -> **Add stack**.
2. Escolha **Upload** e envie o arquivo compactado ou envie a pasta.
3. Se preferir colar o código, selecione **Web editor** e cole o conteúdo de \`docker-compose.yml\`.
4. Clique em **Deploy the stack**.

## Acesso aos Serviços
- **Painel Web SOC:** http://localhost:3000
- **API REST Kali:** http://localhost:8080/api/status
- **PostgreSQL 16:** localhost:5432
`;

export async function downloadCompleteProjectZip(): Promise<void> {
  const zip = new JSZip();

  // Adiciona arquivos do repositório
  for (const [filepath, content] of Object.entries(sourceFiles)) {
    // Normaliza caminho removendo barra inicial
    const cleanPath = filepath.replace(/^\//, '');
    zip.file(cleanPath, content);
  }

  // Adiciona arquivos de deploy para Portainer
  zip.file('docker-compose.yml', DOCKER_COMPOSE_CONTENT);
  zip.file('deploy_all.sh', DEPLOY_SCRIPT_CONTENT);
  zip.file('README.md', README_CONTENT);

  // Gera o arquivo ZIP binário
  const blob = await zip.generateAsync({ 
    type: 'blob',
    compression: 'DEFLATE',
    compressionOptions: { level: 9 }
  });

  // Dispara o download no navegador
  const downloadUrl = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = downloadUrl;
  anchor.download = 'netsentry-kali-soc-complete.zip';
  document.body.appendChild(anchor);
  anchor.click();
  document.body.removeChild(anchor);
  URL.revokeObjectURL(downloadUrl);
}
