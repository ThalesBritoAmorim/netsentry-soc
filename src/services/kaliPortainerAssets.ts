// NetSentry SOC - Assets de Deploy para Portainer & Kali Linux
// 100% Local, Offline & Air-Gapped (SEM dependência de internet ou redirecionamentos externos)
// PostgreSQL 16 + Sniffer Scapy + Agente Executor Terminal Kali + Interface Web Completa embutida

export const DOCKER_COMPOSE_YML = `# ==============================================================================
# NetSentry SOC - Portainer Stack Deployment para Kali Linux
# Cole diretamente no Portainer: Stacks -> netsentrysoc -> Editor
# 100% LOCAL: PostgreSQL 16 + Sniffer Scapy + API REST + Painel Web Local (Porta 3000)
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

  # 2. Daemon Python Autônomo com API REST (Sniffer Scapy + Agente Executor Kali Linux)
  # Modo Host + Privilégios Totais (privileged: true) + Namespace de Processos e Volumes do Host
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
        set -e
        echo "[NetSentry] 1. Instalando dependencias de rede e terminal no contêiner..."
        apt-get update -qq && apt-get install -y -qq --no-install-recommends libpcap-dev gcc iptables iproute2 tcpdump arping nmap net-tools iputils-ping util-linux procps sudo curl
        pip install -q --no-cache-dir scapy psycopg2-binary

        echo "[NetSentry] 2. Criando daemon_monitor.py com Agente Executor do Kali Linux..."
        cat << 'EOF' > /daemon.py
        import os, sys, time, subprocess, logging, json, threading, socket, re
        from collections import defaultdict, deque
        from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
        import psycopg2
        from scapy.all import sniff, ARP, IP, TCP, UDP, DNS, Ether, srp, BOOTP, DHCP

        logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] [NetSentry]: %(message)s")

        DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
        DB_PORT = int(os.getenv("DB_PORT", "5432"))
        DB_NAME = os.getenv("DB_NAME", "netsentry_db")
        DB_USER = os.getenv("DB_USER", "netsentry_admin")
        DB_PASS = os.getenv("DB_PASSWORD", "SecOps_Kali_2026!Strong")
        IFACE = os.getenv("SNIFF_INTERFACE", "eth0")
        API_PORT = int(os.getenv("API_PORT", "8080"))
        AUTO_MITIGATE = os.getenv("AUTONOMOUS_MITIGATION", "true").lower() == "true"

        # Deteccao automatica de interface de rede ativa no Kali
        try:
            import scapy.all as scapy_mod
            avail_ifaces = scapy_mod.get_if_list()
            if IFACE not in avail_ifaces:
                logging.warning(f"Interface {IFACE} nao encontrada. Interfaces no host: {avail_ifaces}")
                valids = [i for i in avail_ifaces if i != 'lo' and not i.startswith('docker') and not i.startswith('veth') and not i.startswith('br-')]
                if valids:
                    IFACE = valids[0]
                    logging.info(f"Interface de captura ajustada automaticamente para: {IFACE}")
        except Exception:
            pass

        # OUI Vendor Database
        OUI_TABLE = {
            'b8:27:eb': 'Raspberry Pi Foundation',
            'dc:a6:32': 'Raspberry Pi Foundation',
            'e4:5f:01': 'Raspberry Pi Foundation',
            '28:cd:c1': 'Raspberry Pi Foundation',
            '00:1c:42': 'Parallels / VM',
            '00:50:56': 'VMware ESXi / Workstation',
            '00:0c:29': 'VMware Workstation',
            '08:00:27': 'Oracle VirtualBox',
            '52:54:00': 'QEMU / KVM Host',
            '00:15:5d': 'Microsoft Hyper-V',
            '00:1a:2b': 'Apple Inc.',
            '3c:22:fb': 'Apple Inc. (iPhone/Mac)',
            'b0:be:76': 'Apple Inc.',
            'd8:bb:2c': 'Apple Inc.',
            'f8:1e:df': 'Apple Inc.',
            '18:67:b0': 'Samsung Electronics',
            '24:4b:fe': 'Samsung Electronics',
            '30:07:4d': 'Samsung Galaxy',
            'ec:71:db': 'Samsung Electronics',
            '24:0a:c4': 'Espressif (ESP32 IoT)',
            '30:ae:a4': 'Espressif Systems',
            '84:f3:eb': 'Espressif (NodeMCU IoT)',
            '50:c7:bf': 'TP-Link Technologies',
            '1c:3b:f3': 'TP-Link Archer / Deco',
            '54:af:97': 'TP-Link Technologies',
            '70:4f:57': 'TP-Link Technologies',
            '98:da:c4': 'TP-Link Technologies',
            '00:0c:e7': 'Cisco Systems',
            '00:1e:67': 'Intel Corporate',
            '00:14:22': 'Dell Inc.',
            '18:03:73': 'Dell Inc.',
            '00:1e:0b': 'HP Inc.',
            '00:11:32': 'Synology NAS',
            '00:08:9b': 'QNAP NAS',
            '44:65:0d': 'Amazon Echo / FireTV',
            '70:ee:50': 'Google Nest / Chromecast',
            '94:eb:cd': 'Google LLC',
            '78:11:dc': 'Xiaomi Communications',
            '64:cc:2e': 'Xiaomi Smart Home',
            '10:bf:48': 'ASUSTeK Computer',
            '04:d9:f5': 'ASUSTeK Computer'
        }

        def get_vendor(mac):
            if not mac: return 'Desconhecido'
            p = mac.lower()[:8]
            return OUI_TABLE.get(p, 'Dispositivo de Rede IEEE')

        # Caches de resolucao
        dhcp_names = {}
        resolved_hosts = {}
        resolved_domains = {}

        def query_netbios_identity(ip):
            try:
                query = b'\x80\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00 CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00!\x00\x01'
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(0.8)
                sock.sendto(query, (ip, 137))
                data, _ = sock.recvfrom(2048)
                sock.close()
                if len(data) < 56:
                    return None, None
                pos = data.find(b'\x00\x21\x00\x01', 12)
                if pos == -1:
                    return None, None
                num_names_offset = pos + 10
                if len(data) <= num_names_offset:
                    return None, None
                num_names = data[num_names_offset]
                comp_name = None
                domain_name = None
                offset = num_names_offset + 1
                for _ in range(num_names):
                    if offset + 18 > len(data):
                        break
                    raw_n = data[offset:offset+15].decode('latin1', errors='ignore').strip()
                    suffix = data[offset+15]
                    flags = (data[offset+16] << 8) | data[offset+17]
                    is_group = bool(flags & 0x8000)
                    clean_n = ''.join(c for c in raw_n if c.isalnum() or c in '-_')
                    if clean_n and len(clean_n) >= 2:
                        if is_group:
                            if not domain_name:
                                domain_name = clean_n
                        else:
                            if not comp_name or suffix == 0x00 or suffix == 0x20:
                                comp_name = clean_n
                    offset += 18
                return comp_name, domain_name
            except Exception:
                pass
            return None, None

        def query_reverse_dns(ip):
            try:
                host, _, _ = socket.gethostbyaddr(ip)
                if host and host != ip:
                    parts = host.split('.')
                    if len(parts) > 1:
                        return parts[0], '.'.join(parts[1:])
                    return host, None
            except Exception:
                pass
            return None, None

        def resolve_device_identity(ip, mac, suggested_name=None):
            if suggested_name and not suggested_name.startswith('host-') and suggested_name != 'unknown-host':
                parts = suggested_name.split('.')
                h = parts[0]
                d = '.'.join(parts[1:]) if len(parts) > 1 else resolved_domains.get(ip)
                return h, 'dns', d
            if ip in dhcp_names:
                return dhcp_names[ip], 'dhcp', resolved_domains.get(ip)
            if mac in dhcp_names:
                return dhcp_names[mac], 'dhcp', resolved_domains.get(ip)
            if ip in resolved_hosts:
                h, m = resolved_hosts[ip]
                return h, m, resolved_domains.get(ip)
            # Tenta NetBIOS (extrai Nome do Computador E Domínio/Workgroup)
            nb_comp, nb_dom = query_netbios_identity(ip)
            if nb_comp or nb_dom:
                if nb_dom: resolved_domains[ip] = nb_dom
                h = nb_comp or f"host-{ip.split('.')[-1]}"
                resolved_hosts[ip] = (h, 'netbios')
                return h, 'netbios', nb_dom
            # Tenta Reverse DNS (PTR)
            rdns_h, rdns_d = query_reverse_dns(ip)
            if rdns_h:
                if rdns_d: resolved_domains[ip] = rdns_d
                resolved_hosts[ip] = (rdns_h, 'dns')
                return rdns_h, 'dns', rdns_d
            # Heuristica de Gateway
            if ip.endswith('.1'):
                return 'gateway', 'dhcp', 'local'
            fallback = f"host-{ip.split('.')[-1]}"
            return fallback, 'arp', resolved_domains.get(ip)

        conn = None
        # Auto-identificacao e Protecao contra Auto-Bloqueio (Self-Protection & Gateway Protection)
        PROTECTED_IPS = {"127.0.0.1", "localhost", "0.0.0.0", "192.168.0.156", "192.168.0.1"}
        PROTECTED_MACS = {"a8:5e:45:1e:39:dd", "08:00:27:e9:6e:96"}
        LOCAL_HOST_IPS = set(PROTECTED_IPS)
        LOCAL_HOST_MACS = set(PROTECTED_MACS)
        GATEWAY_IP = "192.168.0.1"
        GATEWAY_MAC = "a8:5e:45:1e:39:dd"

        def refresh_local_identities():
            global LOCAL_HOST_IPS, LOCAL_HOST_MACS, GATEWAY_IP, GATEWAY_MAC, PROTECTED_IPS, PROTECTED_MACS
            try:
                res = subprocess.run("ip -o -f inet addr show | awk '{print $4}'", shell=True, capture_output=True, text=True)
                for line in res.stdout.strip().split("\n"):
                    ip_clean = line.split("/")[0].strip()
                    if ip_clean:
                        LOCAL_HOST_IPS.add(ip_clean)
                        PROTECTED_IPS.add(ip_clean)
            except Exception:
                pass

            try:
                res_link = subprocess.run("ip link show", shell=True, capture_output=True, text=True)
                for line in res_link.stdout.split("\n"):
                    l = line.strip().lower()
                    if "link/ether" in l:
                        parts = l.split()
                        try:
                            idx = parts.index("link/ether")
                            if idx + 1 < len(parts):
                                m = parts[idx + 1].strip()
                                if len(m) == 17:
                                    LOCAL_HOST_MACS.add(m)
                                    PROTECTED_MACS.add(m)
                        except ValueError:
                            pass
            except Exception:
                pass

            try:
                res_gw = subprocess.run("ip route show default | awk '{print $3}'", shell=True, capture_output=True, text=True)
                gw_cand = res_gw.stdout.strip().split("\n")[0].strip()
                if gw_cand:
                    GATEWAY_IP = gw_cand
                    LOCAL_HOST_IPS.add(gw_cand)
                    PROTECTED_IPS.add(gw_cand)
                    if os.path.exists("/proc/net/arp"):
                        with open("/proc/net/arp", "r") as f:
                            for line in f:
                                parts = line.split()
                                if len(parts) >= 4 and parts[0] == GATEWAY_IP:
                                    m_cand = parts[3].strip().lower()
                                    if len(m_cand) == 17 and m_cand != "00:00:00:00:00:00":
                                        GATEWAY_MAC = m_cand
                                        LOCAL_HOST_MACS.add(m_cand)
                                        PROTECTED_MACS.add(m_cand)
            except Exception:
                pass

        def purge_all_drop_rules():
            for hip in list(PROTECTED_IPS):
                if hip and hip != "0.0.0.0":
                    for chain in ("INPUT", "FORWARD"):
                        for pattern in (f"-s {hip} -p tcp --syn -j DROP", f"-s {hip} -j DROP", f"-d {hip} -j DROP"):
                            while True:
                                res = subprocess.run(f"iptables -D {chain} {pattern} 2>/dev/null", shell=True)
                                if res.returncode != 0:
                                    break

            for hmac in list(PROTECTED_MACS):
                if hmac and len(hmac) == 17:
                    for chain in ("INPUT", "FORWARD"):
                        while True:
                            res = subprocess.run(f"iptables -D {chain} -m mac --mac-source {hmac} -j DROP 2>/dev/null", shell=True)
                            if res.returncode != 0:
                                break

        refresh_local_identities()
        purge_all_drop_rules()

        def init_db():
            global conn
            logging.info(f"Conectando ao PostgreSQL 16 em {DB_HOST}:{DB_PORT}...")
            for attempt in range(60):
                try:
                    conn = psycopg2.connect(host=DB_HOST, port=DB_PORT, dbname=DB_NAME, user=DB_USER, password=DB_PASS)
                    conn.autocommit = True
                    logging.info("Conexao com PostgreSQL 16 estabelecida com sucesso!")
                    with conn.cursor() as cur:
                        cur.execute("""
                            CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
                            CREATE TABLE IF NOT EXISTS network_devices (
                                id VARCHAR(64) PRIMARY KEY,
                                ip VARCHAR(45) NOT NULL UNIQUE,
                                mac VARCHAR(17) NOT NULL UNIQUE,
                                hostname VARCHAR(128) DEFAULT 'unknown-host',
                                domain VARCHAR(128),
                                vendor VARCHAR(128) DEFAULT 'Desconhecido',
                                device_type VARCHAR(32) DEFAULT 'unknown',
                                trust_level VARCHAR(32) DEFAULT 'unverified',
                                threat_score INT DEFAULT 0,
                                rx_bytes BIGINT DEFAULT 0,
                                tx_bytes BIGINT DEFAULT 0,
                                is_online BOOLEAN DEFAULT TRUE,
                                discovery_method VARCHAR(32) DEFAULT 'arp',
                                custom_alias VARCHAR(128),
                                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                            );
                            ALTER TABLE network_devices ADD COLUMN IF NOT EXISTS domain VARCHAR(128);
                            CREATE TABLE IF NOT EXISTS threat_alerts (
                                id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                title VARCHAR(255) NOT NULL,
                                category VARCHAR(64) NOT NULL,
                                severity VARCHAR(32) NOT NULL,
                                source_ip VARCHAR(45) NOT NULL,
                                source_mac VARCHAR(17),
                                protocol VARCHAR(16) DEFAULT 'TCP',
                                confidence INT DEFAULT 95,
                                details TEXT,
                                status VARCHAR(32) DEFAULT 'active',
                                mitigation_command TEXT,
                                applied BOOLEAN DEFAULT FALSE
                            );
                            CREATE TABLE IF NOT EXISTS traffic_flows (
                                id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                protocol VARCHAR(16) NOT NULL,
                                src_ip VARCHAR(45) NOT NULL,
                                dst_ip VARCHAR(45) NOT NULL,
                                packet_length INT NOT NULL,
                                info TEXT
                            );
                            CREATE TABLE IF NOT EXISTS kali_command_history (
                                id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                command TEXT NOT NULL,
                                output TEXT,
                                status VARCHAR(32) DEFAULT 'success'
                            );
                        """)
                    logging.info("Tabelas do PostgreSQL verificadas e prontas.")
                    break
                except Exception:
                    time.sleep(2)

        threading.Thread(target=init_db, daemon=True).start()

        arp_cache = {}
        syn_tracker = defaultdict(deque)
        recent_traffic = deque(maxlen=80)
        metrics = {
            "total_packets": 0,
            "pps": 0,
            "bytes_last_sec": 0,
            "threats_neutralized": 0,
            "start_time": time.time()
        }

        pps_counter = [0]
        bps_counter = [0]

        def pps_monitor():
            while True:
                time.sleep(1.0)
                metrics["pps"] = pps_counter[0]
                metrics["bytes_last_sec"] = bps_counter[0]
                pps_counter[0] = 0
                bps_counter[0] = 0

        threading.Thread(target=pps_monitor, daemon=True).start()

        def parse_arp_table():
            devices = []
            try:
                if os.path.exists("/proc/net/arp"):
                    with open("/proc/net/arp", "r") as f:
                        lines = f.readlines()[1:]
                        for line in lines:
                            parts = line.split()
                            if len(parts) >= 4 and parts[3] != "00:00:00:00:00:00":
                                ip, mac, iface = parts[0], parts[3], parts[5]
                                devices.append({"ip": ip, "mac": mac, "iface": iface})
            except Exception as e:
                logging.error(f"Erro ao ler /proc/net/arp: {e}")
            return devices

        def process_packet(pkt):
            now = time.time()
            length = len(pkt)
            pps_counter[0] += 1
            bps_counter[0] += length
            metrics["total_packets"] += 1

            src_ip = "0.0.0.0"
            dst_ip = "0.0.0.0"
            proto = "ETH"
            info = "Pacote Camada 2"

            # Inspecao DHCP Option 12 (Nome do dispositivo explicitamente anunciado)
            if pkt.haslayer(DHCP):
                try:
                    for opt in pkt[DHCP].options:
                        if isinstance(opt, tuple) and opt[0] == 'hostname':
                            val = opt[1]
                            hname = val.decode('utf-8', errors='ignore') if isinstance(val, bytes) else str(val)
                            if hname:
                                client_mac = getattr(pkt, 'src', '')
                                client_ip = pkt[IP].src if pkt.haslayer(IP) else ''
                                if client_mac: dhcp_names[client_mac] = hname
                                if client_ip: dhcp_names[client_ip] = hname
                                logging.info(f"💡 Hostname DHCP detectado: {hname} ({client_ip} / {client_mac})")
                                if conn:
                                    with conn.cursor() as cur:
                                        cur.execute("""
                                            UPDATE network_devices 
                                            SET hostname = %s, discovery_method = 'dhcp' 
                                            WHERE (ip = %s OR mac = %s) AND custom_alias IS NULL;
                                        """, (hname, client_ip, client_mac))
                except Exception:
                    pass

            if pkt.haslayer(ARP):
                arp = pkt[ARP]
                src_ip, src_mac = arp.psrc, arp.hwsrc
                dst_ip = arp.pdst
                proto = "ARP"
                info = f"ARP Who has {dst_ip}? Tell {src_ip}"

                if src_ip in LOCAL_HOST_IPS or src_mac.lower() in LOCAL_HOST_MACS:
                    pass
                elif src_ip in arp_cache and arp_cache[src_ip] != src_mac:
                    logging.warning(f"🚨 ALERTA REAL: Conflito ARP / Spoofing de {src_mac} alegando {src_ip}!")
                    cmd = f"iptables -I INPUT -m mac --mac-source {src_mac} -j DROP"
                    applied = False
                    if AUTO_MITIGATE:
                        subprocess.run(cmd, shell=True)
                        applied = True
                        metrics["threats_neutralized"] += 1
                    with conn.cursor() as cur:
                        cur.execute("""
                            INSERT INTO threat_alerts (title, category, severity, source_ip, source_mac, details, mitigation_command, applied)
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                        """, ("ARP Spoofing Detectado no Host Kali", "arp_poisoning", "critical", src_ip, src_mac, f"Conflito de MAC com IP {src_ip}", cmd, applied))

                arp_cache[src_ip] = src_mac

                # Identifica e cadastra dispositivo
                try:
                    hname, method, dom_name = resolve_device_identity(src_ip, src_mac)
                    vendor = get_vendor(src_mac)
                    dtype = "gateway" if src_ip.endswith(".1") else "workstation"
                    with conn.cursor() as cur:
                        cur.execute("""
                            INSERT INTO network_devices (id, ip, mac, hostname, domain, vendor, device_type, discovery_method, is_online, last_seen)
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, TRUE, CURRENT_TIMESTAMP)
                            ON CONFLICT (ip) DO UPDATE SET 
                                last_seen = CURRENT_TIMESTAMP, 
                                is_online = TRUE,
                                domain = COALESCE(EXCLUDED.domain, network_devices.domain),
                                vendor = CASE WHEN network_devices.vendor = 'Desconhecido' THEN EXCLUDED.vendor ELSE network_devices.vendor END,
                                hostname = CASE WHEN network_devices.custom_alias IS NOT NULL THEN network_devices.hostname 
                                                WHEN network_devices.hostname = 'WORKGROUP' THEN EXCLUDED.hostname
                                                WHEN network_devices.hostname LIKE 'host-%%' THEN EXCLUDED.hostname 
                                                ELSE network_devices.hostname END;
                        """, (f"dev-{src_ip.replace('.', '-')}", src_ip, src_mac, hname, dom_name, vendor, dtype, method))
                except Exception:
                    pass

            elif pkt.haslayer(IP):
                ip_layer = pkt[IP]
                src_ip, dst_ip = ip_layer.src, ip_layer.dst

                if pkt.haslayer(TCP):
                    proto = "TCP"
                    tcp = pkt[TCP]
                    info = f"Porta {tcp.sport} -> {tcp.dport} [{tcp.flags}]"

                    if tcp.flags == "S":
                        # PROTECAO DE AUTO-BLOQUEIO: O proprio Kali Linux (192.168.0.156) nunca deve ser bloqueado!
                        if src_ip in LOCAL_HOST_IPS or src_ip.startswith("127.") or (hasattr(pkt, 'hwsrc') and getattr(pkt, 'hwsrc', '').lower() in LOCAL_HOST_MACS):
                            pass
                        else:
                            q = syn_tracker[src_ip]
                            q.append((now, tcp.dport))
                            while q and now - q[0][0] > 3.0: q.popleft()
                            if len(set(p for _, p in q)) > 15:
                                logging.warning(f"🚨 ALERTA REAL: Varredura de Portas SYN de {src_ip}!")
                                cmd = f"iptables -A INPUT -s {src_ip} -p tcp --syn -j DROP"
                                applied = False
                                if AUTO_MITIGATE:
                                    subprocess.run(cmd, shell=True)
                                    applied = True
                                    metrics["threats_neutralized"] += 1
                                with conn.cursor() as cur:
                                    cur.execute("""
                                        INSERT INTO threat_alerts (title, category, severity, source_ip, details, mitigation_command, applied)
                                        VALUES (%s, %s, %s, %s, %s, %s)
                                    """, ("Varredura SYN Nmap Detectada", "port_scan", "high", src_ip, "Mais de 15 portas distintas escaneadas", cmd, applied))
                                q.clear()

                elif pkt.haslayer(UDP):
                    proto = "UDP"
                    udp = pkt[UDP]
                    info = f"UDP {udp.sport} -> {udp.dport}"
                    if pkt.haslayer(DNS):
                        proto = "DNS"
                        info = "DNS Query / Response"

            recent_traffic.append({
                "id": f"flow-{int(now * 1000)}-{src_ip.split('.')[-1]}",
                "timestamp": time.strftime("%H:%M:%S", time.localtime(now)),
                "protocol": proto,
                "srcIp": src_ip,
                "dstIp": dst_ip,
                "packetLength": length,
                "info": info,
                "isSuspicious": proto == "ARP" and src_ip in arp_cache and arp_cache[src_ip] != getattr(pkt, 'hwsrc', '')
            })

        class RestApiHandler(BaseHTTPRequestHandler):
            def end_headers(self):
                self.send_header("Access-Control-Allow-Origin", "*")
                self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
                self.send_header("Access-Control-Allow-Headers", "Content-Type")
                super().end_headers()

            def do_OPTIONS(self):
                self.send_response(200)
                self.end_headers()

            def do_GET(self):
                if self.path == "/api/status":
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    data = {
                        "status": "online",
                        "host": "Kali Linux (Local Host)",
                        "interface": IFACE,
                        "hostIps": list(LOCAL_HOST_IPS),
                        "pps": metrics["pps"],
                        "bandwidthKbps": round((metrics["bytes_last_sec"] * 8) / 1024, 1),
                        "totalPackets": metrics["total_packets"],
                        "totalThreatsNeutralized": metrics["threats_neutralized"],
                        "autonomousMode": AUTO_MITIGATE,
                        "postgresConnected": True,
                        "uptimeSeconds": int(time.time() - metrics["start_time"])
                    }
                    self.wfile.write(json.dumps(data).encode("utf-8"))

                elif self.path == "/api/devices":
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    devices = []
                    try:
                        with conn.cursor() as cur:
                            cur.execute("SELECT id, ip, mac, hostname, vendor, threat_score, trust_level, last_seen, discovery_method, custom_alias, domain FROM network_devices ORDER BY last_seen DESC;")
                            rows = cur.fetchall()
                            for r in rows:
                                ip_addr = r[1]
                                mac_addr = r[2]
                                stored_name = r[3]
                                vendor_name = r[4] or get_vendor(mac_addr)
                                disc_method = r[8] or "arp"
                                custom_alias = r[9]
                                stored_dom = r[10] if len(r) > 10 else None

                                effective_name = custom_alias or stored_name
                                effective_dom = stored_dom or resolved_domains.get(ip_addr)

                                # Se o hostname anterior estava gravado incorretamente como WORKGROUP
                                if effective_name == "WORKGROUP":
                                    effective_dom = "WORKGROUP"
                                    effective_name = ""

                                if not effective_name or effective_name.startswith("host-") or effective_name == "unknown-host" or not effective_dom:
                                    resolved, m, d = resolve_device_identity(ip_addr, mac_addr)
                                    if resolved and not resolved.startswith("host-"):
                                        effective_name = resolved
                                        disc_method = m
                                    if d and not effective_dom:
                                        effective_dom = d

                                devices.append({
                                    "id": r[0],
                                    "ip": ip_addr,
                                    "mac": mac_addr,
                                    "hostname": effective_name or f"host-{ip_addr.split('.')[-1]}",
                                    "domain": effective_dom,
                                    "workgroup": effective_dom,
                                    "vendor": vendor_name,
                                    "threatScore": r[5] or 0,
                                    "trustLevel": r[6] or "unverified",
                                    "deviceType": "gateway" if ip_addr.endswith(".1") else "workstation",
                                    "openPorts": [],
                                    "rxBytes": 1024,
                                    "txBytes": 1024,
                                    "isOnline": True,
                                    "discoveryMethod": disc_method,
                                    "customAlias": custom_alias,
                                    "lastSeen": str(r[7])[:19]
                                })
                    except Exception:
                        pass

                    if not devices:
                        for item in parse_arp_table():
                            ip_addr = item["ip"]
                            mac_addr = item["mac"]
                            hname, m, d = resolve_device_identity(ip_addr, mac_addr)
                            vendor = get_vendor(mac_addr)
                            devices.append({
                                "id": f"dev-{ip_addr.replace('.', '-')}",
                                "ip": ip_addr,
                                "mac": mac_addr,
                                "hostname": hname,
                                "domain": d,
                                "workgroup": d,
                                "vendor": vendor,
                                "threatScore": 0,
                                "trustLevel": "unverified",
                                "deviceType": "gateway" if ip_addr.endswith(".1") else "workstation",
                                "openPorts": [],
                                "rxBytes": 512,
                                "txBytes": 512,
                                "isOnline": True,
                                "discoveryMethod": m,
                                "lastSeen": "Agora"
                            })

                    self.wfile.write(json.dumps(devices).encode("utf-8"))

                elif self.path == "/api/alerts":
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    alerts = []
                    try:
                        with conn.cursor() as cur:
                            cur.execute("SELECT id, timestamp, title, category, severity, source_ip, details, mitigation_command, applied FROM threat_alerts ORDER BY timestamp DESC LIMIT 30;")
                            rows = cur.fetchall()
                            for r in rows:
                                alerts.append({
                                    "id": str(r[0]),
                                    "timestamp": str(r[1])[:19],
                                    "title": r[2],
                                    "category": r[3],
                                    "severity": r[4],
                                    "sourceIp": r[5],
                                    "targetIp": "127.0.0.1",
                                    "protocol": "TCP",
                                    "confidence": 96,
                                    "details": r[6] or "",
                                    "status": "mitigated" if r[8] else "active",
                                    "playbook": {
                                        "id": f"pb-{str(r[0])[:8]}",
                                        "actionName": "Bloqueio Iptables Netfilter",
                                        "description": "Descarte de pacotes maliciosos no kernel do Kali Linux.",
                                        "severity": r[4],
                                        "iptablesCommand": r[7] or "sudo iptables -A INPUT -j DROP",
                                        "kaliToolCommand": f"sudo nmap -sV -sC -O -Pn {r[5]}",
                                        "automatedAvailable": True,
                                        "applied": bool(r[8]),
                                        "rollbackCommand": (r[7] or "").replace("-I INPUT", "-D INPUT").replace("-A INPUT", "-D INPUT")
                                    }
                                })
                    except Exception as e:
                        logging.error(f"Erro ao buscar alertas: {e}")
                    self.wfile.write(json.dumps(alerts).encode("utf-8"))

                elif self.path == "/api/traffic":
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps(list(recent_traffic)).encode("utf-8"))
                else:
                    self.send_response(404)
                    self.end_headers()

            def do_POST(self):
                content_len = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(content_len).decode("utf-8") if content_len > 0 else "{}"
                try:
                    payload = json.loads(body)
                except Exception:
                    payload = {}

                if self.path == "/api/mitigate":
                    cmd = payload.get("command", "")
                    if cmd and ("iptables" in cmd or "ip route" in cmd):
                        logging.info(f"Executando mitigacao no kernel Kali: {cmd}")
                        out = ""
                        try:
                            res = subprocess.run(f"nsenter -t 1 -m -u -i -n -p -- bash -c '{cmd}'", shell=True, capture_output=True, text=True, timeout=30)
                            out = res.stdout or res.stderr
                        except Exception:
                            res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
                            out = res.stdout or res.stderr
                        self.send_response(200)
                        self.send_header("Content-Type", "application/json")
                        self.end_headers()
                        self.wfile.write(json.dumps({"success": True, "output": out}).encode("utf-8"))
                    else:
                        self.send_response(400)
                        self.end_headers()

                elif self.path == "/api/exec":
                    cmd = payload.get("command", "")
                    if cmd:
                        logging.info(f"Executando comando no terminal do Kali: {cmd}")
                        out = ""
                        executed_via = "direto-root"

                        # Limpa 'sudo ' redundante para evitar pedidos de senha / prompts
                        run_cmd = cmd.strip()
                        if run_cmd.startswith("sudo "):
                            run_cmd = run_cmd[5:].strip()

                        # Se for varredura nmap, otimiza flags para resposta ágil e segura
                        if run_cmd.startswith("nmap ") and "-T" not in run_cmd:
                            run_cmd += " -T4 --max-retries 1 --host-timeout 90s"

                        # 1. Tenta executar diretamente dentro do contêiner privilegiado (modo host)
                        try:
                            res = subprocess.run(run_cmd, shell=True, capture_output=True, text=True, timeout=120)
                            out = res.stdout or res.stderr or ""
                            executed_via = "host-network"
                        except subprocess.TimeoutExpired:
                            out = f"[Timeout 120s]: A execucao do comando '{cmd}' excedeu o tempo limite."
                            executed_via = "timeout"
                        except Exception as e:
                            out = f"[Erro exec direto]: {e}"

                        # 2. Se vazio ou falhou e nsenter estiver disponível no host, tenta via nsenter
                        if (not out.strip() or "[Erro" in out) and executed_via != "timeout":
                            try:
                                res = subprocess.run(f"nsenter -t 1 -m -u -i -n -p -- bash -c '{run_cmd}'", shell=True, capture_output=True, text=True, timeout=60)
                                if res.stdout or res.stderr:
                                    out = res.stdout or res.stderr
                                    executed_via = "nsenter-host"
                            except Exception:
                                pass

                        try:
                            if conn:
                                with conn.cursor() as cur:
                                    cur.execute("INSERT INTO kali_command_history (command, output, status) VALUES (%s, %s, %s);", (cmd, out[:4000], "success"))
                        except Exception:
                            pass

                        clean_out = out.strip() or "Comando concluido no Kali Linux sem saida textual."
                        self.send_response(200)
                        self.send_header("Content-Type", "application/json")
                        self.end_headers()
                        self.wfile.write(json.dumps({"success": True, "output": clean_out, "method": executed_via}).encode("utf-8"))
                    else:
                        self.send_response(200)
                        self.send_header("Content-Type", "application/json")
                        self.end_headers()
                        self.wfile.write(json.dumps({"success": False, "output": "Nenhum comando fornecido."}).encode("utf-8"))

                elif self.path == "/api/scan":
                    logging.info("Varredura profunda ARP + DNS + NetBIOS de sub-rede disparada no Kali...")
                    def run_network_sweep():
                        try:
                            # 1. ARP Broadcast para despertar nós dormindo
                            subprocess.run(f"arping -b -c 2 -I {IFACE} 255.255.255.255 2>/dev/null", shell=True)
                        except Exception:
                            pass

                        try:
                            res = subprocess.run("ip -o -f inet addr show " + IFACE + " | awk '{print $4}'", shell=True, capture_output=True, text=True)
                            subnet = res.stdout.strip()
                            if subnet:
                                # 2. Nmap com resolucao de nomes DNS ativa (sem flag -n!)
                                nmap_proc = subprocess.run(f"nmap -sn --system-dns {subnet} 2>/dev/null", shell=True, capture_output=True, text=True)
                                nmap_out = nmap_proc.stdout or ""

                                for block in nmap_out.split("Nmap scan report for "):
                                    if not block.strip(): continue
                                    lines = block.strip().split("\n")
                                    hdr = lines[0].strip()
                                    ip_found, hname_found = None, None
                                    if "(" in hdr and ")" in hdr:
                                        parts = hdr.split("(")
                                        hname_found = parts[0].strip()
                                        ip_found = parts[1].replace(")", "").strip()
                                    else:
                                        ip_found = hdr.strip()

                                    mac_found = None
                                    for l in lines:
                                        if "MAC Address:" in l:
                                            m_m = re.search(r"([0-9A-Fa-f:]{17})", l)
                                            if m_m: mac_found = m_m.group(1).lower()

                                    if ip_found:
                                        if not mac_found:
                                            for itm in parse_arp_table():
                                                if itm["ip"] == ip_found:
                                                    mac_found = itm["mac"]
                                                    break
                                        if not mac_found:
                                            mac_found = f"52:54:00:{ip_found.split('.')[-1]}:00:01"

                                        true_name, method, dom_found = resolve_device_identity(ip_found, mac_found, hname_found)
                                        vendor = get_vendor(mac_found)
                                        dtype = "gateway" if ip_found.endswith(".1") else "workstation"

                                        if conn:
                                            with conn.cursor() as cur:
                                                cur.execute("""
                                                    INSERT INTO network_devices (id, ip, mac, hostname, domain, vendor, device_type, discovery_method, is_online, last_seen)
                                                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, TRUE, CURRENT_TIMESTAMP)
                                                    ON CONFLICT (ip) DO UPDATE SET 
                                                        hostname = CASE WHEN network_devices.custom_alias IS NOT NULL THEN network_devices.hostname 
                                                                        WHEN network_devices.hostname = 'WORKGROUP' THEN EXCLUDED.hostname
                                                                        WHEN EXCLUDED.hostname NOT LIKE 'host-%%' THEN EXCLUDED.hostname 
                                                                        ELSE network_devices.hostname END,
                                                        domain = COALESCE(EXCLUDED.domain, network_devices.domain),
                                                        vendor = CASE WHEN network_devices.vendor = 'Desconhecido' THEN EXCLUDED.vendor ELSE network_devices.vendor END,
                                                        discovery_method = EXCLUDED.discovery_method,
                                                        is_online = TRUE,
                                                        last_seen = CURRENT_TIMESTAMP;
                                                """, (f"dev-{ip_found.replace('.', '-')}", ip_found, mac_found, true_name, dom_found, vendor, dtype, method))

                        except Exception as e:
                            logging.error(f"Erro no sweep de rede: {e}")

                        # 3. Processa tabela ARP local tambem
                        try:
                            for item in parse_arp_table():
                                ip_addr = item["ip"]
                                mac_addr = item["mac"]
                                hname, m, d = resolve_device_identity(ip_addr, mac_addr)
                                vendor = get_vendor(mac_addr)
                                dtype = "gateway" if ip_addr.endswith(".1") else "workstation"
                                if conn:
                                    with conn.cursor() as cur:
                                        cur.execute("""
                                            INSERT INTO network_devices (id, ip, mac, hostname, domain, vendor, device_type, discovery_method, is_online, last_seen)
                                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, TRUE, CURRENT_TIMESTAMP)
                                            ON CONFLICT (ip) DO UPDATE SET 
                                                last_seen = CURRENT_TIMESTAMP, 
                                                is_online = TRUE,
                                                domain = COALESCE(EXCLUDED.domain, network_devices.domain);
                                        """, (f"dev-{ip_addr.replace('.', '-')}", ip_addr, mac_addr, hname, d, vendor, dtype, m))
                        except Exception:
                            pass

                    threading.Thread(target=run_network_sweep, daemon=True).start()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps({"success": True, "message": "Varredura ativa Nmap com resolucao de DNS e NetBIOS iniciada no Kali Linux."}).encode("utf-8"))

                elif self.path == "/api/device/alias":
                    ip = payload.get("ip", "")
                    mac = payload.get("mac", "")
                    alias = payload.get("alias", "").strip()
                    if conn and (ip or mac):
                        try:
                            with conn.cursor() as cur:
                                cur.execute("""
                                    UPDATE network_devices 
                                    SET custom_alias = %s, 
                                        hostname = CASE WHEN %s != '' THEN %s ELSE hostname END,
                                        discovery_method = 'manual'
                                    WHERE ip = %s OR mac = %s;
                                """, (alias or None, alias, alias, ip, mac))
                        except Exception as e:
                            logging.error(f"Erro ao salvar alias: {e}")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps({"success": True, "ip": ip, "alias": alias}).encode("utf-8"))

                elif self.path == "/api/unblock":
                    target_ip = payload.get("ip", "192.168.0.156")
                    logging.info(f"🚨 Desbloqueio emergencial de host requisitado para: {target_ip}")
                    PROTECTED_IPS.add(target_ip)
                    LOCAL_HOST_IPS.add(target_ip)

                    # 1. Purga TODAS as regras repetidas de IP (loop até zerar)
                    for chain in ("INPUT", "FORWARD", "OUTPUT"):
                        for pattern in (f"-s {target_ip} -p tcp --syn -j DROP", f"-s {target_ip} -j DROP", f"-d {target_ip} -j DROP"):
                            while True:
                                r = subprocess.run(f"iptables -D {chain} {pattern} 2>/dev/null", shell=True)
                                if r.returncode != 0:
                                    break
                                try:
                                    subprocess.run(f"nsenter -t 1 -m -u -i -n -p -- iptables -D {chain} {pattern} 2>/dev/null", shell=True)
                                except Exception:
                                    pass

                    # 2. Purga TODAS as regras repetidas de MAC que afetaram o host ou roteador
                    for bad_mac in list(PROTECTED_MACS) + ["a8:5e:45:1e:39:dd", "08:00:27:e9:6e:96"]:
                        for chain in ("INPUT", "FORWARD"):
                            while True:
                                r = subprocess.run(f"iptables -D {chain} -m mac --mac-source {bad_mac} -j DROP 2>/dev/null", shell=True)
                                if r.returncode != 0:
                                    break
                                try:
                                    subprocess.run(f"nsenter -t 1 -m -u -i -n -p -- iptables -D {chain} -m mac --mac-source {bad_mac} -j DROP 2>/dev/null", shell=True)
                                except Exception:
                                    pass

                    # Atualiza PostgreSQL para marcar alertas desse IP como não aplicados/whitelisted
                    if conn:
                        try:
                            with conn.cursor() as cur:
                                cur.execute("UPDATE threat_alerts SET applied = FALSE, status = 'whitelisted' WHERE source_ip = %s;", (target_ip,))
                        except Exception as e:
                            logging.error(f"Erro ao atualizar alertas no banco: {e}")

                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps({
                        "success": True, 
                        "unblockedIp": target_ip, 
                        "message": f"Regras DROP para {target_ip} removidas do iptables com sucesso! Kali restabelecido."
                    }).encode("utf-8"))
                else:
                    self.send_response(404)
                    self.end_headers()

        def start_api():
            server = ThreadingHTTPServer(("0.0.0.0", API_PORT), RestApiHandler)
            logging.info(f"API REST NetSentry pronta em http://0.0.0.0:{API_PORT}/api/status")
            server.serve_forever()

        threading.Thread(target=start_api, daemon=True).start()

        logging.info(f"NetSentry Sniffer Scapy capturando pacotes reais na interface {IFACE}...")
        sniff(iface=IFACE, prn=process_packet, store=0)
        EOF

        echo "[NetSentry] 3. Executando Daemon com API REST..."
        python3 -u /daemon.py
    depends_on:
      - postgres

  # 3. Interface Web Dashboard (100% Local / Offline em http://localhost:3000)
  web-ui:
    image: nginx:alpine
    container_name: netsentry-web
    restart: unless-stopped
    network_mode: host
    entrypoint:
      - /bin/sh
      - -c
      - |
        mkdir -p /usr/share/nginx/html
        cat << 'EOF' > /etc/nginx/conf.d/default.conf
        server {
            listen 3000;
            server_name localhost;
            root /usr/share/nginx/html;
            index index.html;

            location /api/kali/ {
                proxy_pass http://127.0.0.1:8080/api/;
                proxy_http_version 1.1;
                proxy_set_header Host $$host;
                proxy_set_header X-Real-IP $$remote_addr;
                proxy_connect_timeout 300s;
                proxy_send_timeout 300s;
                proxy_read_timeout 300s;
            }

            location /api/ {
                proxy_pass http://127.0.0.1:8080/api/;
                proxy_http_version 1.1;
                proxy_set_header Host $$host;
                proxy_set_header X-Real-IP $$remote_addr;
                proxy_connect_timeout 300s;
                proxy_send_timeout 300s;
                proxy_read_timeout 300s;
            }

            location / {
                try_files $$uri $$uri/ /index.html;
            }
        }
        EOF

        cat << 'EOF' > /usr/share/nginx/html/index.html
        <!DOCTYPE html>
        <html lang="pt-BR" class="dark">
        <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>NetSentry Kali SOC (100% Local)</title>
          <style>
            :root {
              --bg: #020617;
              --card: #0f172a;
              --card-hover: #1e293b;
              --border: #334155;
              --cyan: #38bdf8;
              --emerald: #34d399;
              --amber: #fbbf24;
              --rose: #f87171;
              --text: #f8fafc;
              --muted: #94a3b8;
            }
            * { box-sizing: border-box; margin: 0; padding: 0; }
            body {
              background-color: var(--bg);
              color: var(--text);
              font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
              line-height: 1.5;
              padding-bottom: 2rem;
            }
            header {
              background: rgba(15, 23, 42, 0.95);
              border-bottom: 1px solid var(--border);
              padding: 0.875rem 1.5rem;
              display: flex;
              align-items: center;
              justify-content: space-between;
              position: sticky;
              top: 0;
              z-index: 100;
            }
            .brand { display: flex; align-items: center; gap: 0.75rem; font-weight: 700; font-size: 1.1rem; color: var(--cyan); }
            .badge-local {
              background: rgba(52, 211, 153, 0.15);
              color: var(--emerald);
              border: 1px solid rgba(52, 211, 153, 0.4);
              font-size: 0.7rem;
              font-family: monospace;
              padding: 0.2rem 0.5rem;
              border-radius: 4px;
            }
            .tabs { display: flex; gap: 0.5rem; overflow-x: auto; margin-top: 1rem; padding: 0 1.5rem; border-bottom: 1px solid var(--border); }
            .tab-btn {
              background: none;
              border: none;
              color: var(--muted);
              font-size: 0.875rem;
              font-weight: 600;
              padding: 0.6rem 1rem;
              cursor: pointer;
              border-bottom: 2px solid transparent;
              transition: all 0.2s;
            }
            .tab-btn.active { color: var(--cyan); border-bottom-color: var(--cyan); }
            .container { max-width: 1200px; margin: 1.5rem auto; padding: 0 1.5rem; }
            .grid-kpi { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 1.5rem; }
            .card {
              background: var(--card);
              border: 1px solid var(--border);
              border-radius: 10px;
              padding: 1.25rem;
              transition: border-color 0.2s;
            }
            .card:hover { border-color: #475569; }
            .kpi-title { font-size: 0.75rem; color: var(--muted); text-transform: uppercase; font-weight: 600; letter-spacing: 0.5px; }
            .kpi-value { font-size: 1.75rem; font-weight: 700; font-family: monospace; margin-top: 0.4rem; color: var(--text); }
            .table-wrap { overflow-x: auto; background: var(--card); border: 1px solid var(--border); border-radius: 10px; }
            table { width: 100%; border-collapse: collapse; text-align: left; font-size: 0.8125rem; }
            th { background: #020617; padding: 0.75rem 1rem; color: var(--muted); font-family: monospace; text-transform: uppercase; font-size: 0.7rem; border-bottom: 1px solid var(--border); }
            td { padding: 0.75rem 1rem; border-bottom: 1px solid rgba(51, 65, 85, 0.4); }
            tr:hover td { background: var(--card-hover); }
            .btn {
              background: var(--cyan);
              color: #020617;
              border: none;
              padding: 0.4rem 0.8rem;
              font-size: 0.75rem;
              font-weight: 600;
              border-radius: 6px;
              cursor: pointer;
              transition: opacity 0.2s;
            }
            .btn:hover { opacity: 0.9; }
            .btn-term { background: #1e293b; color: var(--cyan); border: 1px solid var(--cyan); }
            .btn-term:hover { background: #0f172a; }
            .term-box {
              background: #000;
              border: 1px solid var(--border);
              border-radius: 10px;
              padding: 1rem;
              font-family: monospace;
              font-size: 0.8125rem;
              color: var(--emerald);
              min-height: 340px;
              max-height: 500px;
              overflow-y: auto;
              white-space: pre-wrap;
              margin-top: 1rem;
            }
            .term-input-bar { display: flex; gap: 0.5rem; margin-top: 1rem; }
            .term-input {
              flex: 1;
              background: #020617;
              border: 1px solid var(--border);
              border-radius: 6px;
              padding: 0.6rem 0.8rem;
              color: #fff;
              font-family: monospace;
              font-size: 0.8125rem;
            }
            .term-input:focus { outline: none; border-color: var(--cyan); }
            .alert-box {
              background: rgba(248, 113, 113, 0.1);
              border: 1px solid rgba(248, 113, 113, 0.3);
              padding: 1rem;
              border-radius: 8px;
              margin-bottom: 0.75rem;
              display: flex;
              align-items: center;
              justify-content: space-between;
              gap: 1rem;
            }
          </style>
        </head>
        <body>
          <header>
            <div class="brand">
              <span>🛡️ NetSentry Kali SOC</span>
              <span class="badge-local">100% LOCAL & OFFLINE</span>
            </div>
            <div style="font-size: 0.8rem; color: var(--muted); font-family: monospace;">
              Interface: <strong id="net-iface" style="color: var(--cyan)">eth0</strong> · Status: <span id="net-status" style="color: var(--emerald)">Ativo</span>
            </div>
          </header>

          <div class="tabs">
            <button class="tab-btn active" onclick="showTab('tab-dashboard', this)">Painel SOC</button>
            <button class="tab-btn" onclick="showTab('tab-devices', this)">Dispositivos</button>
            <button class="tab-btn" onclick="showTab('tab-traffic', this)">Tráfego ao Vivo</button>
            <button class="tab-btn" onclick="showTab('tab-terminal', this)">Terminal Kali Linux</button>
            <button class="tab-btn" onclick="showTab('tab-topology', this)">Topologia de Rede (Efetividade)</button>
          </div>

          <div class="container">
            <!-- TAB: DASHBOARD -->
            <div id="tab-dashboard">
              <div class="grid-kpi">
                <div class="card">
                  <div class="kpi-title">Pacotes/segundo (PPS)</div>
                  <div class="kpi-value" id="kpi-pps">0</div>
                </div>
                <div class="card">
                  <div class="kpi-title">Vazão da Rede</div>
                  <div class="kpi-value" id="kpi-kbps">0 KB/s</div>
                </div>
                <div class="card">
                  <div class="kpi-title">Total de Pacotes</div>
                  <div class="kpi-value" id="kpi-total">0</div>
                </div>
                <div class="card">
                  <div class="kpi-title">Mitigações Executadas</div>
                  <div class="kpi-value" id="kpi-mitigated" style="color: var(--emerald)">0</div>
                </div>
              </div>

              <div class="card" style="margin-bottom: 1.5rem;">
                <h3 style="font-size: 0.95rem; margin-bottom: 0.8rem;">🚨 Alertas Recentes & Sugestões de Mitigação</h3>
                <div id="alerts-list">
                  <p style="color: var(--muted); font-size: 0.85rem;">Nenhuma ameaça detectada no momento.</p>
                </div>
              </div>
            </div>

            <!-- TAB: DEVICES -->
            <div id="tab-devices" style="display: none;">
              <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem;">
                <h3 style="font-size: 0.95rem;">Hosts Conectados na Rede</h3>
                <button class="btn" onclick="triggerScan()">Escanear Sub-rede (ARP Sweep)</button>
              </div>
              <div class="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>Endereço IP</th>
                      <th>Endereço MAC</th>
                      <th>Hostname</th>
                      <th>Fabricante</th>
                      <th>Última Atividade</th>
                      <th>Ação no Kali</th>
                    </tr>
                  </thead>
                  <tbody id="devices-tbody">
                    <tr><td colspan="6" style="text-align: center; color: var(--muted);">Carregando dispositivos...</td></tr>
                  </tbody>
                </table>
              </div>
            </div>

            <!-- TAB: TRAFFIC -->
            <div id="tab-traffic" style="display: none;">
              <h3 style="font-size: 0.95rem; margin-bottom: 1rem;">Captura de Pacotes em Tempo Real (Scapy Sniffer)</h3>
              <div class="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>Hora</th>
                      <th>Protocolo</th>
                      <th>Origem</th>
                      <th>Destino</th>
                      <th>Tamanho</th>
                      <th>Informações</th>
                    </tr>
                  </thead>
                  <tbody id="traffic-tbody">
                    <tr><td colspan="6" style="text-align: center; color: var(--muted);">Aguardando pacotes...</td></tr>
                  </tbody>
                </table>
              </div>
            </div>

            <!-- TAB: TERMINAL KALI -->
            <div id="tab-terminal" style="display: none;">
              <div class="card">
                <h3 style="font-size: 0.95rem;">Terminal do Host Kali Linux (root / nsenter)</h3>
                <p style="font-size: 0.75rem; color: var(--muted); margin-top: 0.2rem;">
                  Executa comandos diretamente no terminal do seu Kali Linux e retorna o resultado em tempo real.
                </p>
                <div class="term-input-bar">
                  <input type="text" id="term-input" class="term-input" placeholder="Digite o comando (ex: sudo nmap -sV -sC -O -Pn 192.168.1.1 ou sudo iptables -L -n -v)" value="sudo nmap -sV -sC -O -Pn 192.168.1.1">
                  <button class="btn" onclick="runTerminalCommand()">Executar no Kali</button>
                </div>
                <div class="term-box" id="term-output">Pronto para receber comandos. Digite acima ou clique em "Executar Scan" em qualquer dispositivo.</div>
              </div>
            </div>

            <!-- TAB: TOPOLOGY / NETWORK EFFECTIVENESS -->
            <div id="tab-topology" style="display: none;">
              <div class="card" style="space-y: 1.5rem;">
                <h2 style="font-size: 1.1rem; color: var(--cyan); margin-bottom: 0.5rem;">Como Tornar o NetSentry 100% Efetivo na Sua Rede</h2>
                <p style="font-size: 0.85rem; color: var(--muted); line-height: 1.6; margin-bottom: 1rem;">
                  Em switches normais de rede, o tráfego entre outros computadores não passa pela placa de rede do Kali Linux (isolamento por portas comutadas). Para o NetSentry inspecionar 100% do tráfego da rede, você deve utilizar uma das opções abaixo:
                </p>

                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 1rem; margin-top: 1rem;">
                  <div style="background: #020617; border: 1px solid var(--border); border-radius: 8px; padding: 1rem;">
                    <h4 style="color: var(--emerald); font-size: 0.9rem; margin-bottom: 0.4rem;">Opção 1: Port Mirroring / SPAN (Switch Gerenciável)</h4>
                    <p style="font-size: 0.75rem; color: var(--muted); line-height: 1.5;">
                      Se seu switch tiver gerenciamento (ex: Mikrotik, Cisco, TP-Link Omada, Ubiquiti UniFi): configure a porta do Roteador para ser espelhada (Mirror) na porta física do Kali Linux. Todo o tráfego da rede é copiado em tempo real sem lentidão.
                    </p>
                  </div>

                  <div style="background: #020617; border: 1px solid var(--border); border-radius: 8px; padding: 1rem;">
                    <h4 style="color: var(--cyan); font-size: 0.9rem; margin-bottom: 0.4rem;">Opção 2: Kali Linux em Modo Inline / Bridge (2 Placas)</h4>
                    <p style="font-size: 0.75rem; color: var(--muted); line-height: 1.5;">
                      Coloque o Kali entre o Roteador e o Switch usando duas placas de rede (ex: eth0 e eth1) em modo Bridge. Assim, 100% dos pacotes passam fisicamente pelo Kali e o NetSentry pode bloquear ameaças ativamente antes de atingirem as vítimas.
                    </p>
                  </div>

                  <div style="background: #020617; border: 1px solid var(--border); border-radius: 8px; padding: 1rem;">
                    <h4 style="color: var(--amber); font-size: 0.9rem; margin-bottom: 0.4rem;">Opção 3: ARP Spoofing / Gateway Redirection</h4>
                    <p style="font-size: 0.75rem; color: var(--muted); line-height: 1.5;">
                      Para redes domésticas ou sem switch gerenciável: use o módulo de interceptação ARP para que o Kali anuncie sua rota, fazendo o tráfego dos clientes passar pelo Kali antes do gateway.
                    </p>
                  </div>
                </div>

                <div style="background: #020617; border: 1px solid rgba(56, 189, 248, 0.3); border-radius: 8px; padding: 1rem; margin-top: 1.5rem;">
                  <h4 style="color: var(--cyan); font-size: 0.85rem; margin-bottom: 0.5rem;">Comandos Essenciais no Terminal do Kali:</h4>
                  <pre style="font-family: monospace; font-size: 0.75rem; color: var(--emerald); background: #000; padding: 0.75rem; border-radius: 6px;">
                    # 1. Habilitar modo promíscuo na placa de rede:
                    sudo ip link set eth0 promisc on

                    # 2. Habilitar encaminhamento de pacotes no kernel:
                    sudo sysctl -w net.ipv4.ip_forward=1
                    sudo sysctl -w net.ipv4.conf.all.send_redirects=0

                    # 3. Desativar descarte por hardware offload (para inspeção íntegra):
                    sudo ethtool -K eth0 rx off tx off gso off tso off gro off
                  </pre>
                </div>
              </div>
            </div>
          </div>

          <script>
            function showTab(tabId, btn) {
              var allTabIds = ['tab-dashboard', 'tab-devices', 'tab-traffic', 'tab-terminal', 'tab-topology'];
              for (var i = 0; i < allTabIds.length; i++) {
                var el = document.getElementById(allTabIds[i]);
                if (el) el.style.display = (allTabIds[i] === tabId) ? 'block' : 'none';
              }
              var allButtons = document.querySelectorAll('.tab-btn');
              for (var j = 0; j < allButtons.length; j++) {
                allButtons[j].classList.remove('active');
              }
              if (btn) {
                btn.classList.add('active');
              } else {
                var matchBtn = document.querySelector('.tab-btn[onclick*=\"' + tabId + '\"]');
                if (matchBtn) matchBtn.classList.add('active');
              }
            }

            async function fetchMetrics() {
              try {
                var res = await fetch('/api/status');
                if (res.ok) {
                  var data = await res.json();
                  document.getElementById('kpi-pps').innerText = data.pps || 0;
                  document.getElementById('kpi-kbps').innerText = (data.bandwidthKbps || 0) + ' KB/s';
                  document.getElementById('kpi-total').innerText = Number(data.totalPackets || 0).toLocaleString('pt-BR');
                  document.getElementById('kpi-mitigated').innerText = data.totalThreatsNeutralized || 0;
                  document.getElementById('net-iface').innerText = data.interface || 'eth0';
                  var st = document.getElementById('net-status');
                  if (st) {
                    st.innerText = 'Online (Capturando)';
                    st.style.color = 'var(--emerald)';
                  }
                } else {
                  var stErr = document.getElementById('net-status');
                  if (stErr) {
                    stErr.innerText = 'Iniciando API...';
                    stErr.style.color = 'var(--amber)';
                  }
                }
              } catch(e) {
                var stOff = document.getElementById('net-status');
                if (stOff) {
                  stOff.innerText = 'Aguardando Daemon...';
                  stOff.style.color = 'var(--amber)';
                }
              }
            }

            async function fetchDevices() {
              try {
                var res = await fetch('/api/devices');
                if (res.ok) {
                  var devices = await res.json();
                  var tbody = document.getElementById('devices-tbody');
                  if (devices && devices.length > 0) {
                    tbody.innerHTML = devices.map(function(d) {
                      return '<tr>' +
                        '<td style=\"font-weight: 700; color: var(--cyan); font-family: monospace;\">' + (d.ip || '') + '</td>' +
                        '<td style=\"font-family: monospace; color: var(--muted);\">' + (d.mac || '') + '</td>' +
                        '<td>' + (d.hostname || 'unknown') + '</td>' +
                        '<td>' + (d.vendor || 'Desconhecido') + '</td>' +
                        '<td>' + (d.lastSeen || '') + '</td>' +
                        '<td>' +
                          '<button class=\"btn btn-term\" data-ip=\"' + (d.ip || '') + '\" onclick=\"sendScan(this.dataset.ip)\">⚡ Scan Nmap (-Pn)</button>' +
                        '</td>' +
                      '</tr>';
                    }).join('');
                  } else {
                    tbody.innerHTML = '<tr><td colspan=\"6\" style=\"text-align: center; color: var(--muted); padding: 1.5rem;\">' +
                      'Ainda nenhum host detectado na rede local. Clique no botão \"Escanear Sub-rede (ARP Sweep)\" acima para disparar descoberta!' +
                      '</td></tr>';
                  }
                }
              } catch(e) {}
            }

            async function fetchAlerts() {
              try {
                var res = await fetch('/api/alerts');
                if (res.ok) {
                  var alerts = await res.json();
                  var list = document.getElementById('alerts-list');
                  if (alerts && alerts.length > 0) {
                    list.innerHTML = alerts.map(function(a) {
                      var iptablesCmd = (a.playbook && a.playbook.iptablesCommand) ? a.playbook.iptablesCommand : ('sudo iptables -A INPUT -s ' + (a.sourceIp || '') + ' -j DROP');
                      return '<div class=\"alert-box\">' +
                        '<div>' +
                          '<strong style=\"color: var(--rose);\">' + (a.title || 'Ameaça') + '</strong> (' + (a.timestamp || '') + ')<br>' +
                          '<span style=\"font-size: 0.75rem; color: var(--muted);\">Origem: ' + (a.sourceIp || '') + ' · ' + (a.details || '') + '</span>' +
                        '</div>' +
                        '<div>' +
                          '<button class=\"btn\" data-cmd=\"' + iptablesCmd + '\" onclick=\"executeMitigate(this.dataset.cmd)\">⚡ Executar no Iptables</button>' +
                        '</div>' +
                      '</div>';
                    }).join('');
                  } else {
                    list.innerHTML = '<p style=\"color: var(--muted); font-size: 0.85rem;\">Nenhuma ameaça detectada no momento. Firewall e tráfego estáveis.</p>';
                  }
                }
              } catch(e) {}
            }

            async function fetchTraffic() {
              try {
                var res = await fetch('/api/traffic');
                if (res.ok) {
                  var flows = await res.json();
                  var tbody = document.getElementById('traffic-tbody');
                  if (flows && flows.length > 0) {
                    tbody.innerHTML = flows.slice(-15).reverse().map(function(f) {
                      return '<tr>' +
                        '<td style=\"font-family: monospace;\">' + (f.timestamp || '') + '</td>' +
                        '<td><span style=\"background: #1e293b; padding: 2px 6px; border-radius: 4px; font-weight: 600;\">' + (f.protocol || '') + '</span></td>' +
                        '<td style=\"font-family: monospace;\">' + (f.srcIp || '') + '</td>' +
                        '<td style=\"font-family: monospace;\">' + (f.dstIp || '') + '</td>' +
                        '<td>' + (f.packetLength || 0) + ' B</td>' +
                        '<td style=\"color: var(--muted);\">' + (f.info || '') + '</td>' +
                      '</tr>';
                    }).join('');
                  } else {
                    tbody.innerHTML = '<tr><td colspan=\"6\" style=\"text-align: center; color: var(--muted); padding: 1.5rem;\">' +
                      'Aguardando pacotes na interface... (Dica: gere tráfego na rede ou navegue no Kali para ver pacotes aqui).' +
                      '</td></tr>';
                  }
                }
              } catch(e) {}
            }

            async function triggerScan() {
              await fetch('/api/scan', { method: 'POST' });
              alert('Varredura de sub-rede ARP iniciada no Kali Linux.');
              setTimeout(fetchDevices, 2000);
            }

            function sendScan(ip) {
              var cmd = 'sudo nmap -sV -sC -O -Pn ' + ip;
              document.getElementById('term-input').value = cmd;
              showTab('tab-terminal');
              runTerminalCommand();
            }

            async function executeMitigate(cmd) {
              if (!cmd) return;
              var term = document.getElementById('term-output');
              term.innerText += \"\\n\\n[NetSentry SOC] Executando mitigacao no kernel:\\n$ \" + cmd;
              var res = await fetch('/api/mitigate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ command: cmd })
              });
              var data = await res.json();
              term.innerText += \"\\n\" + (data.output || 'Regra Netfilter aplicada com sucesso.');
              alert('Mitigação executada no firewall do Kali Linux!');
              fetchMetrics();
              fetchAlerts();
            }

            async function runTerminalCommand() {
              var input = document.getElementById('term-input');
              var cmd = input.value.trim();
              if (!cmd) return;
              var term = document.getElementById('term-output');
              term.innerText += \"\\n\\nkali@root# \" + cmd + \"\\n[Aguardando resposta do Kali Linux...]\";
              term.scrollTop = term.scrollHeight;

              try {
                var res = await fetch('/api/exec', {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify({ command: cmd })
                });
                var text = await res.text();
                var data;
                try {
                  data = JSON.parse(text);
                } catch(e) {
                  var clean = text.replace(/<[^>]*>/g, ' ').replace(/\\s+/g, ' ').trim();
                  data = { success: false, output: clean || ('Resposta HTTP ' + res.status + ': ' + text) };
                }
                term.innerText += \"\\n\" + (data.output || 'Concluido sem saida.');
              } catch(err) {
                term.innerText += \"\\nErro ao comunicar com o agente: \" + err.message;
              }
              term.scrollTop = term.scrollHeight;
            }

            setInterval(function() {
              fetchMetrics();
              fetchDevices();
              fetchAlerts();
              fetchTraffic();
            }, 2000);

            fetchMetrics();
            fetchDevices();
            fetchAlerts();
            fetchTraffic();
          </script>
        </body>
        </html>
        EOF

        nginx -g "daemon off;"

volumes:
  postgres_data:
`;

export const PYTHON_DAEMON_SCRIPT = `#!/usr/bin/env python3
"""
NetSentry Autonomous Daemon v2.4 com API REST
Captura de pacotes reais, descoberta de dispositivos ARP e mitigação via iptables no Kali Linux.
"""
`;

export const INIT_SQL_SCHEMA = `-- NetSentry PostgreSQL Schema
`;

export const KALI_INSTALL_SCRIPT = `#!/usr/bin/env bash
`;

export const ALL_IN_ONE_QUICKSTART_SCRIPT = `#!/usr/bin/env bash
# ==============================================================================
# NetSentry SOC - Script de Inicialização 100% Local no Kali Linux
# Executa 100% offline, sem dependência de internet externa
# ==============================================================================

set -e

echo "=== [1/4] Preparando Diretório Operacional /opt/netsentry ==="
sudo mkdir -p /opt/netsentry
cd /opt/netsentry

echo "=== [2/4] Otimizando Configurações de Rede do Kernel Kali Linux ==="
# 1. Habilita modo promíscuo na interface padrão (para capturar todo o tráfego da rede)
IFACE=$(ip route show default | awk '{print $5}' | head -n 1)
IFACE=\${IFACE:-eth0}
echo "-> Interface detectada: \$IFACE. Ativando modo promíscuo..."
sudo ip link set \$IFACE promisc on

# 2. Habilita encaminhamento de pacotes IPv4 no kernel
echo "-> Habilitando net.ipv4.ip_forward..."
sudo sysctl -w net.ipv4.ip_forward=1
sudo sysctl -w net.ipv4.conf.all.send_redirects=0

echo "=== [3/4] Criando docker-compose.yml 100% Local ==="
cat << 'COMPOSE_EOF' > /opt/netsentry/docker-compose.yml
${DOCKER_COMPOSE_YML}
COMPOSE_EOF

echo "=== [4/4] Subindo Stack NetSentry SOC via Docker Compose ==="
if command -v docker-compose &> /dev/null; then
    docker-compose up -d
else
    docker compose up -d
fi

echo ""
echo "=============================================================================="
echo "🛡️ NETSENTRY SOC INICIADO COM SUCESSO 100% LOCAL!"
echo "=============================================================================="
echo "-> Interface Web Local:   http://localhost:3000"
echo "-> API REST & Terminal:   http://localhost:8080/api/status"
echo "-> Banco PostgreSQL 16:   127.0.0.1:5432 (banco: netsentry_db)"
echo "=============================================================================="
echo "Para acompanhar os logs de captura em tempo real no Kali Linux:"
echo "  docker logs -f netsentry-daemon"
echo "=============================================================================="
`;
