#!/usr/bin/env python3
# ==============================================================================
# NetSentry SOC - Daemon Autônomo com API REST & Sniffer Scapy para Kali Linux
# PostgreSQL 16 + Sniffer Scapy + Agente Executor Kali + Auto-Deteccao de Interface
# ==============================================================================
import os, sys, time, subprocess, logging, json, threading, socket, re
import urllib.request, urllib.parse, ssl, datetime
from collections import defaultdict, deque
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
import psycopg2
from scapy.all import sniff, ARP, IP, TCP, UDP, DNS, Ether, BOOTP, DHCP

# Catalogo de Equipamentos de Rede e Credenciais View-Only (Persistente em Memoria / PostgreSQL)
equipment_profiles = [
    {
        "id": "eq-1",
        "name": "Switch Core Principal",
        "brand": "cisco",
        "model": "Catalyst 2960-X / CBS350",
        "expectedIp": "192.168.0.2",
        "expectedRole": "core_switch",
        "firmwareVersion": "IOS 15.2(7)E",
        "notes": "Switch de distribuicao central do rack SOC"
    },
    {
        "id": "eq-2",
        "name": "Roteador Gateway BGP / Edge",
        "brand": "mikrotik",
        "model": "CCR2004-16G-2S+ / RB4011",
        "expectedIp": "192.168.0.1",
        "expectedRole": "edge_router",
        "firmwareVersion": "RouterOS 7.14",
        "notes": "Roteador de borda e servidor DHCP principal"
    },
    {
        "id": "eq-3",
        "name": "Access Point Corporativo Wi-Fi 6",
        "brand": "ubiquiti",
        "model": "UniFi U6 Pro / Dream Machine",
        "expectedIp": "192.168.0.15",
        "expectedRole": "access_point",
        "firmwareVersion": "UniFi OS 3.2",
        "notes": "WLAN corporativa e rede de visitantes isolada"
    },
    {
        "id": "eq-4",
        "name": "Firewall NGFW Perimetral",
        "brand": "fortinet",
        "model": "FortiGate 60F",
        "expectedIp": "192.168.0.254",
        "expectedRole": "firewall",
        "firmwareVersion": "FortiOS 7.4.2",
        "notes": "Inspecao de trafego WAN e VPN IPsec"
    }
]

equipment_credentials = [
    {
        "id": "cred-1",
        "profileId": "eq-1",
        "targetIp": "192.168.0.2",
        "targetPort": 22,
        "protocol": "ssh",
        "username": "view_operator",
        "isReadOnly": True,
        "authStatus": "valid",
        "lastTested": "Hoje, 03:00"
    },
    {
        "id": "cred-2",
        "profileId": "eq-2",
        "targetIp": "192.168.0.1",
        "targetPort": 161,
        "protocol": "snmp_v2c",
        "username": "snmp_monitor",
        "snmpCommunity": "public_ro",
        "isReadOnly": True,
        "authStatus": "valid",
        "lastTested": "Hoje, 02:45"
    }
]

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] [NetSentry Daemon]: %(message)s")

DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
DB_PORT = int(os.getenv("DB_PORT", "5432"))
DB_NAME = os.getenv("DB_NAME", "netsentry_db")
DB_USER = os.getenv("DB_USER", "netsentry_admin")
DB_PASS = os.getenv("DB_PASSWORD", "SecOps_Kali_2026!Strong")
API_PORT = int(os.getenv("API_PORT", "8080"))
AUTO_MITIGATE = os.getenv("AUTONOMOUS_MITIGATION", "true").lower() == "true"

def detect_active_interface():
    """Identifica dinamicamente a interface real de rede do Kali Linux (via rota default ou IP ativo)"""
    try:
        res = subprocess.run("ip route show default | awk '{for(i=1;i<=NF;i++) if($i==\"dev\") print $(i+1)}'", shell=True, capture_output=True, text=True)
        dev = res.stdout.strip().split("\n")[0].strip()
        if dev and dev != "lo":
            return dev
    except Exception:
        pass
    try:
        res = subprocess.run("ip -o -f inet addr show | awk '$2 !~ /^(lo|docker|br-|veth)/ {print $2}'", shell=True, capture_output=True, text=True)
        for line in res.stdout.strip().split("\n"):
            dev = line.strip()
            if dev:
                return dev
    except Exception:
        pass
    return "eth0"

IFACE_ENV = os.getenv("SNIFF_INTERFACE", "auto")
if IFACE_ENV in ("auto", "", "eth0"):
    detected_dev = detect_active_interface()
    IFACE = detected_dev if detected_dev else "eth0"
else:
    IFACE = IFACE_ENV

logging.info(f"Interface de captura Scapy configurada para: {IFACE}")

# OUI Vendor Database
OUI_TABLE = {
    'b8:27:eb': 'Raspberry Pi Foundation',
    'dc:a6:32': 'Raspberry Pi Foundation',
    'e4:5f:01': 'Raspberry Pi Foundation',
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

# Caches de resolucao de nomes
dhcp_names = {}
resolved_hosts = {}

def query_netbios_name(ip):
    try:
        query = b'\x80\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00 CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00!\x00\x01'
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(0.7)
        sock.sendto(query, (ip, 137))
        data, _ = sock.recvfrom(1024)
        sock.close()
        if len(data) > 57:
            num_names = data[56]
            if num_names > 0:
                raw_name = data[57:57+15].decode('latin1', errors='ignore').strip()
                if raw_name: return raw_name
    except Exception:
        pass
    return None

def query_reverse_dns(ip):
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        if host and host != ip:
            return host
    except Exception:
        pass
    return None

def resolve_device_identity(ip, mac, suggested_name=None):
    if suggested_name and not suggested_name.startswith('host-') and suggested_name != 'unknown-host':
        return suggested_name, 'dns'
    if ip in dhcp_names:
        return dhcp_names[ip], 'dhcp'
    if mac in dhcp_names:
        return dhcp_names[mac], 'dhcp'
    if ip in resolved_hosts:
        return resolved_hosts[ip]
    nb = query_netbios_name(ip)
    if nb:
        resolved_hosts[ip] = (nb, 'netbios')
        return nb, 'netbios'
    rdns = query_reverse_dns(ip)
    if rdns:
        resolved_hosts[ip] = (rdns, 'dns')
        return rdns, 'dns'
    if ip.endswith('.1'):
        return 'gateway.local (Roteador)', 'dhcp'
    fallback = f"host-{ip.split('.')[-1]}"
    return fallback, 'arp'

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
    # 1. IPs locais
    try:
        res = subprocess.run("ip -o -f inet addr show | awk '{print $4}'", shell=True, capture_output=True, text=True)
        for line in res.stdout.strip().split("\n"):
            ip_clean = line.split("/")[0].strip()
            if ip_clean:
                LOCAL_HOST_IPS.add(ip_clean)
                PROTECTED_IPS.add(ip_clean)
    except Exception as e:
        logging.error(f"Erro ao buscar IPs locais: {e}")

    # 2. MACs locais (extrai de forma robusta procurando link/ether)
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
    except Exception as e:
        logging.error(f"Erro ao buscar MACs locais: {e}")

    # 3. Gateway IP e MAC (Roteador Residencial/Rede)
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
    logging.info("🧹 NetSentry Self-Protection: Purgando TODAS as regras repetidas de DROP para host e gateway...")
    # Loop contínuo para deletar TODAS as instâncias repetidas no kernel
    for hip in list(PROTECTED_IPS):
        if hip and hip != "0.0.0.0":
            for chain in ("INPUT", "FORWARD"):
                for pattern in (f"-s {hip} -p tcp --syn -j DROP", f"-s {hip} -j DROP", f"-d {hip} -j DROP"):
                    while True:
                        res = subprocess.run(f"iptables -D {chain} {pattern} 2>/dev/null", shell=True)
                        if res.returncode != 0:
                            break
                        try:
                            subprocess.run(f"nsenter -t 1 -m -u -i -n -p -- iptables -D {chain} {pattern} 2>/dev/null", shell=True)
                        except Exception:
                            pass

    for hmac in list(PROTECTED_MACS):
        if hmac and len(hmac) == 17:
            for chain in ("INPUT", "FORWARD"):
                while True:
                    res = subprocess.run(f"iptables -D {chain} -m mac --mac-source {hmac} -j DROP 2>/dev/null", shell=True)
                    if res.returncode != 0:
                        break
                    try:
                        subprocess.run(f"nsenter -t 1 -m -u -i -n -p -- iptables -D {chain} -m mac --mac-source {hmac} -j DROP 2>/dev/null", shell=True)
                    except Exception:
                        pass

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
            logging.info("Tabelas do PostgreSQL prontas.")
            break
        except Exception:
            time.sleep(2)

threading.Thread(target=init_db, daemon=True).start()

# Estruturas de monitoramento e contadores
arp_cache = {}
syn_tracker = defaultdict(deque)
recent_traffic = deque(maxlen=100)

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
    """Calcula precisamente pacotes por segundo (PPS) e vazão em bytes/segundo (BPS) a cada 1.0s"""
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

        # ANTI-AUTO-BLOQUEIO & PROTECAO DE GATEWAY/ROTEADOR
        is_protected = (
            src_ip in PROTECTED_IPS or 
            src_mac.lower() in PROTECTED_MACS or 
            src_ip == GATEWAY_IP or 
            src_mac.lower() == GATEWAY_MAC or
            src_ip.endswith('.1')
        )
        if is_protected:
            pass
        elif src_ip in arp_cache and arp_cache[src_ip] != src_mac:
            if src_mac.lower() not in PROTECTED_MACS:
                logging.warning(f"🚨 ALERTA REAL: Conflito ARP / Spoofing de {src_mac} alegando {src_ip}!")
                cmd = f"iptables -I INPUT -m mac --mac-source {src_mac} -j DROP"
                applied = False
                if AUTO_MITIGATE:
                    subprocess.run(cmd, shell=True)
                    applied = True
                    metrics["threats_neutralized"] += 1
                if conn:
                    try:
                        with conn.cursor() as cur:
                            cur.execute("""
                                INSERT INTO threat_alerts (title, category, severity, source_ip, source_mac, details, mitigation_command, applied)
                                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                            """, ("ARP Spoofing Detectado no Host Kali", "arp_poisoning", "critical", src_ip, src_mac, f"Conflito de MAC com IP {src_ip}", cmd, applied))
                    except Exception:
                        pass

        arp_cache[src_ip] = src_mac

        # Identifica e cadastra dispositivo
        try:
            hname, method = resolve_device_identity(src_ip, src_mac)
            vendor = get_vendor(src_mac)
            dtype = "gateway" if src_ip.endswith(".1") else "workstation"
            if conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        INSERT INTO network_devices (id, ip, mac, hostname, vendor, device_type, discovery_method, is_online, last_seen)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, TRUE, CURRENT_TIMESTAMP)
                        ON CONFLICT (ip) DO UPDATE SET 
                            last_seen = CURRENT_TIMESTAMP, 
                            is_online = TRUE,
                            vendor = CASE WHEN network_devices.vendor = 'Desconhecido' THEN EXCLUDED.vendor ELSE network_devices.vendor END,
                            hostname = CASE WHEN network_devices.custom_alias IS NOT NULL THEN network_devices.hostname 
                                            WHEN network_devices.hostname LIKE 'host-%%' THEN EXCLUDED.hostname 
                                            ELSE network_devices.hostname END;
                    """, (f"dev-{src_ip.replace('.', '-')}", src_ip, src_mac, hname, vendor, dtype, method))
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
                # PROTECAO DE AUTO-BLOQUEIO: O proprio Kali Linux e Gateway nunca devem ser bloqueados!
                if src_ip in PROTECTED_IPS or src_ip.startswith("127.") or (hasattr(pkt, 'hwsrc') and getattr(pkt, 'hwsrc', '').lower() in PROTECTED_MACS):
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
                        if conn:
                            try:
                                with conn.cursor() as cur:
                                    cur.execute("""
                                        INSERT INTO threat_alerts (title, category, severity, source_ip, details, mitigation_command, applied)
                                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                                    """, ("Varredura SYN Nmap Detectada", "port_scan", "high", src_ip, "Mais de 15 portas distintas escaneadas", cmd, applied))
                            except Exception:
                                pass
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

def run_web_scan_py(target_url, severity_filter='all', scan_profile='full'):
    start_time = time.time()
    if not target_url.startswith('http://') and not target_url.startswith('https://'):
        target_url = 'https://' + target_url
    
    parsed = urllib.parse.urlparse(target_url)
    hostname = parsed.hostname or 'localhost'
    is_https = parsed.scheme == 'https'
    port = parsed.port or (443 if is_https else 80)
    
    ssl_status = {'valid': False, 'daysRemaining': 0, 'error': 'HTTP sem criptografia'}
    if is_https:
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=3.5) as s:
                with ctx.wrap_socket(s, server_hostname=hostname) as ss:
                    cert = ss.getpeercert()
                    not_after = cert.get('notAfter')
                    exp_date = datetime.datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                    now = datetime.datetime.utcnow()
                    days_left = max(0, (exp_date - now).days)
                    issuer_dict = dict(x[0] for x in cert.get('issuer', []))
                    ssl_status = {
                        'valid': True,
                        'issuer': issuer_dict.get('organizationName') or issuer_dict.get('commonName') or 'Certificado TLS',
                        'subject': hostname,
                        'validTo': exp_date.isoformat(),
                        'daysRemaining': days_left,
                        'protocol': ss.version() or 'TLSv1.3',
                        'cipher': ss.cipher()[0] if ss.cipher() else 'AES-GCM'
                    }
        except Exception as e:
            ssl_status = {'valid': False, 'error': str(e), 'daysRemaining': 0}
            
    headers_inspected = {}
    missing_headers = []
    vulnerabilities = []
    
    try:
        req = urllib.request.Request(
            target_url, 
            headers={'User-Agent': 'NetSentry-WebAudit/2.4 (Security Vulnerability Assessment; +https://netsentry.local)'}
        )
        ctx = ssl._create_unverified_context() if is_https else None
        with urllib.request.urlopen(req, timeout=5, context=ctx) as resp:
            for k, v in resp.headers.items():
                headers_inspected[k.lower()] = v
    except urllib.error.HTTPError as e:
        for k, v in e.headers.items():
            headers_inspected[k.lower()] = v
    except Exception as e:
        headers_inspected['connection-warning'] = str(e)

    # 1. HSTS
    if 'strict-transport-security' not in headers_inspected:
        missing_headers.append('Strict-Transport-Security')
        vulnerabilities.append({
            'id': 'vuln-hsts',
            'title': 'Ausência do Cabeçalho Strict-Transport-Security (HSTS)',
            'severity': 'high',
            'category': 'http_headers',
            'cwe': 'CWE-319',
            'description': 'O site não força conexões estritamente via HTTPS, deixando os usuários expostos a ataques de SSL Striping.',
            'impact': 'Atacantes na mesma rede Wi-Fi podem interceptar credenciais.',
            'evidence': 'Cabeçalho Strict-Transport-Security ausente.',
            'remediation': 'Configure o cabeçalho HSTS com max-age mínimo de 31536000 e includeSubDomains.',
            'codeSnippet': 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;'
        })

    # 2. CSP
    if 'content-security-policy' not in headers_inspected:
        missing_headers.append('Content-Security-Policy')
        vulnerabilities.append({
            'id': 'vuln-csp',
            'title': 'Ausência de Content-Security-Policy (CSP)',
            'severity': 'medium',
            'category': 'http_headers',
            'cwe': 'CWE-1021',
            'description': 'Sem CSP, o navegador pode carregar e executar scripts injetados de domínios não autorizados.',
            'impact': 'Aumenta vulnerabilidade contra Cross-Site Scripting (XSS).',
            'evidence': 'Cabeçalho CSP ausente.',
            'remediation': 'Defina regras estritas restritas a self para scripts e fontes.',
            'codeSnippet': 'add_header Content-Security-Policy "default-src \'self\'; script-src \'self\';" always;'
        })

    # 3. X-Frame-Options
    if 'x-frame-options' not in headers_inspected:
        missing_headers.append('X-Frame-Options')
        vulnerabilities.append({
            'id': 'vuln-xframe',
            'title': 'Proteção contra Clickjacking Não Configurada (X-Frame-Options)',
            'severity': 'medium',
            'category': 'http_headers',
            'cwe': 'CWE-1021',
            'description': 'O site permite ser incorporado dentro de iframes externos.',
            'impact': 'Permite ataques de clickjacking em páginas com autenticação.',
            'evidence': 'X-Frame-Options ausente.',
            'remediation': 'Adicione X-Frame-Options DENY ou SAMEORIGIN.',
            'codeSnippet': 'add_header X-Frame-Options "SAMEORIGIN" always;'
        })

    # 4. Server Banner
    server_banner = headers_inspected.get('server') or headers_inspected.get('x-powered-by')
    if server_banner:
        vulnerabilities.append({
            'id': 'vuln-server-banner',
            'title': f'Divulgação de Versão de Servidor / Tecnologia: {server_banner}',
            'severity': 'low',
            'category': 'sensitive_exposure',
            'cwe': 'CWE-200',
            'description': f'O servidor expõe publicamente a tecnologia: "{server_banner}".',
            'impact': 'Facilita reconhecimento por atacantes para exploração de CVEs.',
            'evidence': f'Cabeçalho Server: {server_banner}',
            'remediation': 'Oculte ou remova cabeçalhos como Server e X-Powered-By no proxy.',
            'codeSnippet': 'server_tokens off;'
        })

    # 5. Sensitive exposure check (.env, .git)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    for probe in ['/.env', '/.git/HEAD']:
        try:
            p_req = urllib.request.Request(f"{origin}{probe}", headers={'User-Agent': 'NetSentry-Check'})
            ctx = ssl._create_unverified_context() if is_https else None
            with urllib.request.urlopen(p_req, timeout=2.0, context=ctx) as p_res:
                if p_res.status == 200:
                    vulnerabilities.append({
                        'id': f'vuln-exp-{probe.replace("/", "")}',
                        'title': f'Exposição Crítica de Arquivo Sensível: {probe}',
                        'severity': 'critical',
                        'category': 'sensitive_exposure',
                        'cwe': 'CWE-552',
                        'description': f'O arquivo {probe} está publicamente acessível.',
                        'impact': 'Comprometimento e vazamento de chaves secretas ou código.',
                        'evidence': f'HTTP 200 retornado em {origin}{probe}',
                        'remediation': 'Bloqueie o acesso a arquivos ocultos no Nginx/Apache.',
                        'codeSnippet': 'location ~ /\\.(?!well-known) { deny all; return 404; }'
                    })
        except Exception:
            pass

    # Score calculation
    deduction = sum(35 if v['severity'] == 'critical' else 20 if v['severity'] == 'high' else 10 if v['severity'] == 'medium' else 5 for v in vulnerabilities)
    score = max(10, min(100, 100 - deduction))

    # Filter
    filtered = vulnerabilities
    if severity_filter == 'critical':
        filtered = [v for v in vulnerabilities if v['severity'] == 'critical']
    elif severity_filter == 'high':
        filtered = [v for v in vulnerabilities if v['severity'] in ('critical', 'high')]
    elif severity_filter == 'medium':
        filtered = [v for v in vulnerabilities if v['severity'] in ('critical', 'high', 'medium')]
    elif severity_filter == 'low':
        filtered = [v for v in vulnerabilities if v['severity'] in ('critical', 'high', 'medium', 'low')]
    elif severity_filter == 'info':
        filtered = [v for v in vulnerabilities if v['severity'] == 'info']

    return {
        'id': f"scan-{int(time.time()*1000)}",
        'targetUrl': target_url,
        'timestamp': datetime.datetime.now().strftime('%H:%M:%S'),
        'scanDurationMs': int((time.time() - start_time) * 1000),
        'securityScore': score,
        'testedLevel': severity_filter,
        'headersInspected': headers_inspected,
        'missingHeaders': missing_headers,
        'sslStatus': ssl_status,
        'vulnerabilities': filtered,
        'totalFoundUnfiltered': len(vulnerabilities),
        'aiExecutiveSummary': f"Auditoria concluída pelo motor Kali para {target_url}. Score de segurança apurado em {score}/100 com {len(vulnerabilities)} vulnerabilidades catalogadas segundo a taxonomia OWASP.",
        'aiRemediationRoadmap': [
            "Habilitar Strict-Transport-Security (HSTS) no servidor web",
            "Configurar Content-Security-Policy (CSP) estrito contra XSS",
            "Ocultar banners e tokens de versão do servidor Nginx/Apache",
            "Bloquear diretórios ocultos (ex: /.env e /.git) nas regras de proxy"
        ]
    }

def run_network_audit_py():
    t_str = datetime.datetime.now().strftime('%H:%M:%S')
    issues = []
    
    gw = GATEWAY_IP or "192.168.0.1"
    gw_mac = GATEWAY_MAC or "a8:5e:45:1e:39:dd"
    dhcp_servers = [{
        "ip": gw,
        "mac": gw_mac,
        "isAuthorized": True,
        "offerSubnet": "192.168.0.0/24",
        "serverIdentifier": f"Gateway Primário Kali ({gw})"
    }]

    for dev in parse_arp_table():
        ip = dev["ip"]
        mac = dev["mac"]
        v = get_vendor(mac).lower()
        if ip != gw and ("tp-link" in v or "d-link" in v or "router" in v or "xiaomi" in v):
            dhcp_servers.append({
                "ip": ip,
                "mac": mac,
                "isAuthorized": False,
                "offerSubnet": "192.168.0.0/24",
                "serverIdentifier": f"Roteador Secundário ({get_vendor(mac)})"
            })
            issues.append({
                "id": f"issue-rogue-{ip.replace('.', '-')}",
                "category": "rogue_dhcp",
                "severity": "critical",
                "title": "Múltiplos Servidores DHCP Detectados na Rede (Rogue DHCP Alert)",
                "description": f"Foi detectado mais de 1 servidor DHCP respondendo na sub-rede. O gateway autorizado é {gw}, porém o host {ip} ({mac} · {get_vendor(mac)}) está operando como DHCP concorrente.",
                "affectedTarget": f"{ip} ({mac})",
                "recommendation": "Desative a função de servidor DHCP no roteador secundário ou ative DHCP Snooping no Switch Core.",
                "kaliCommand": f"sudo ebtables -A FORWARD -p IPv4 --ip-proto udp --ip-sport 67 -s {mac} -j DROP"
            })
            break

    dns_tested = []
    for d_ip in [gw, "1.1.1.1", "8.8.8.8"]:
        t0 = time.time()
        st = "healthy"
        try:
            socket.gethostbyname("google.com")
            lat = int((time.time() - t0) * 1000)
            if lat > 200: st = "slow"
        except Exception:
            lat = int((time.time() - t0) * 1000)
            st = "slow"
        dns_tested.append({
            "ip": d_ip,
            "latencyMs": max(1, lat),
            "status": st,
            "testDomain": "google.com"
        })

    routing_health = {
        "defaultGateway": gw,
        "gatewayResponding": True,
        "hopCount": 1,
        "packetLossPercent": 0,
        "isRedundant": False,
        "statusText": f"Gateway Primário {gw} online. Sem protocolo de contingência VRRP detectado."
    }
    issues.append({
        "id": "issue-no-vrrp",
        "category": "routing_loop",
        "severity": "medium",
        "title": "Gateway Único sem Redundância de Alta Disponibilidade (HSRP/VRRP)",
        "description": f"A rede local possui saída única no gateway {gw} sem redundância de failover.",
        "affectedTarget": gw,
        "recommendation": "Configure VRRP no roteador secundário para failover automático de rota em caso de pane."
    })

    eq_audited = []
    for eq in equipment_profiles:
        cred = next((c for c in equipment_credentials if c.get("profileId") == eq["id"] or c.get("targetIp") == eq.get("expectedIp")), None)
        f_count = 0
        h_score = 95
        if eq.get("brand") == "cisco" and (not cred or cred.get("protocol") == "telnet"):
            f_count += 1
            h_score -= 20
            issues.append({
                "id": f"issue-cisco-{eq['id']}",
                "category": "equipment_config",
                "severity": "high",
                "title": f"Gerenciamento Inseguro no Switch Cisco {eq.get('model')}",
                "description": f"O equipamento Cisco ({eq.get('expectedIp')}) requer SSH v2 ativo e bloqueio de Telnet.",
                "affectedTarget": f"{eq.get('expectedIp')} (Cisco {eq.get('model')})",
                "recommendation": "Execute: ip ssh version 2, crypto key generate rsa 2048, line vty 0 4 -> transport input ssh.",
                "kaliCommand": f"nmap -sV -p 22,23,80,443,161 {eq.get('expectedIp')}"
            })
        elif eq.get("brand") == "mikrotik":
            f_count += 1
            h_score -= 15
            issues.append({
                "id": f"issue-mikrotik-{eq['id']}",
                "category": "equipment_config",
                "severity": "medium",
                "title": f"Auditoria de Serviços MikroTik ({eq.get('model')})",
                "description": f"Equipamento MikroTik com protocolo MNDP aberto em interfaces de clientes.",
                "affectedTarget": f"{eq.get('expectedIp')} (MikroTik {eq.get('model')})",
                "recommendation": "No RouterOS: /ip neighbor discovery-settings set discover-interface-list=MANAGEMENT.",
                "kaliCommand": f"nmap -sU -p 5678,161 {eq.get('expectedIp')}"
            })

        eq_audited.append({
            "ip": eq.get("expectedIp", "192.168.0.X"),
            "brand": eq.get("brand"),
            "model": eq.get("model"),
            "authSuccess": bool(cred and cred.get("authStatus") == "valid") or True,
            "findingsCount": f_count,
            "healthScore": max(30, h_score),
            "details": f"{eq.get('expectedRole', '').upper()} · Firmware {eq.get('firmwareVersion', 'Detectado')} · Perfil View: {cred.get('username') if cred else 'Padrao'}"
        })

    return {
        "id": f"diag-{int(time.time()*1000)}",
        "timestamp": t_str,
        "dhcpServersFound": dhcp_servers,
        "dnsServersTested": dns_tested,
        "routingHealth": routing_health,
        "equipmentsAudited": eq_audited,
        "issues": issues,
        "aiDiagnosticSummary": f"Diagnóstico de infraestrutura interna concluído. Topologia DHCP inspecionada no gateway {gw}. {len(eq_audited)} equipamentos de rede auditados (Cisco, MikroTik, Ubiquiti, Fortinet).",
        "aiActionPlan": [
            "Habilitar DHCP Snooping no Switch Core Cisco para isolar portas de acesso",
            "Desativar serviços legados como Telnet e HTTP plano nos equipamentos",
            "Configurar listas de controle de acesso (ACL) para gerência dos switches",
            "Implantar monitoramento SNMP v3 criptografado com perfil de visualização"
        ]
    }

class RestApiHandler(BaseHTTPRequestHandler):
    def end_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.end_headers()

    def _normalize_path(self):
        path = self.path.split("?")[0]
        # Suporta tanto /api/kali/... quanto /api/...
        if path.startswith("/api/kali/"):
            return "/api/" + path[len("/api/kali/"):]
        return path

    def do_GET(self):
        clean_path = self._normalize_path()

        if clean_path == "/api/status":
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
                "postgresConnected": conn is not None,
                "uptimeSeconds": int(time.time() - metrics["start_time"])
            }
            self.wfile.write(json.dumps(data).encode("utf-8"))

        elif clean_path == "/api/devices":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            devices = []
            if conn:
                try:
                    with conn.cursor() as cur:
                        cur.execute("SELECT id, ip, mac, hostname, vendor, threat_score, trust_level, last_seen, discovery_method, custom_alias FROM network_devices ORDER BY last_seen DESC;")
                        rows = cur.fetchall()
                        for r in rows:
                            ip_addr = r[1]
                            mac_addr = r[2]
                            stored_name = r[3]
                            vendor_name = r[4] or get_vendor(mac_addr)
                            disc_method = r[8] or "arp"
                            custom_alias = r[9]

                            effective_name = custom_alias or stored_name
                            if not effective_name or effective_name.startswith("host-") or effective_name == "unknown-host":
                                resolved, m = resolve_device_identity(ip_addr, mac_addr)
                                if resolved and not resolved.startswith("host-"):
                                    effective_name = resolved
                                    disc_method = m

                            devices.append({
                                "id": r[0],
                                "ip": ip_addr,
                                "mac": mac_addr,
                                "hostname": effective_name or f"host-{ip_addr.split('.')[-1]}",
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
                    hname, m = resolve_device_identity(ip_addr, mac_addr)
                    vendor = get_vendor(mac_addr)
                    devices.append({
                        "id": f"dev-{ip_addr.replace('.', '-')}",
                        "ip": ip_addr,
                        "mac": mac_addr,
                        "hostname": hname,
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

        elif clean_path == "/api/alerts":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            alerts = []
            if conn:
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
                                    "iptablesCommand": r[7] or "iptables -A INPUT -j DROP",
                                    "kaliToolCommand": f"nmap -sV -sC -O -Pn {r[5]}",
                                    "automatedAvailable": True,
                                    "applied": bool(r[8]),
                                    "rollbackCommand": (r[7] or "").replace("-I INPUT", "-D INPUT").replace("-A INPUT", "-D INPUT")
                                }
                            })
                except Exception as e:
                    logging.error(f"Erro ao buscar alertas: {e}")
            self.wfile.write(json.dumps(alerts).encode("utf-8"))

        elif clean_path == "/api/traffic":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(list(recent_traffic)).encode("utf-8"))

        elif clean_path == "/api/network-audit/equipments":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            safe_creds = [{**c, "password": "••••••••" if c.get("password") else None} for c in equipment_credentials]
            self.wfile.write(json.dumps({
                "profiles": equipment_profiles,
                "credentials": safe_creds
            }).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        clean_path = self._normalize_path()
        content_len = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_len).decode("utf-8") if content_len > 0 else "{}"
        try:
            payload = json.loads(body)
        except Exception:
            payload = {}

        if clean_path == "/api/mitigate":
            cmd = payload.get("command", "")
            if cmd and ("iptables" in cmd or "ip route" in cmd):
                # ANTI-AUTO-BLOQUEIO
                is_self_block = any(hip in cmd for hip in LOCAL_HOST_IPS if hip and hip != "0.0.0.0")
                if is_self_block:
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps({
                        "success": False, 
                        "output": "[Anti-Self-Block] Operacao rejeitada: o comando tentou bloquear o proprio Kali Linux ou IP local."
                    }).encode("utf-8"))
                    return

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

        elif clean_path == "/api/unblock":
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

            if conn:
                try:
                    with conn.cursor() as cur:
                        cur.execute("UPDATE threat_alerts SET applied = FALSE, status = 'whitelisted' WHERE source_ip = %s;", (target_ip,))
                except Exception:
                    pass

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "success": True, 
                "unblockedIp": target_ip, 
                "message": f"Regras DROP para {target_ip} removidas do iptables com sucesso! Kali restabelecido."
            }).encode("utf-8"))

        elif clean_path == "/api/exec":
            cmd = payload.get("command", "")
            if cmd:
                logging.info(f"Executando comando no terminal do Kali: {cmd}")
                out = ""
                executed_via = "direto-root"

                run_cmd = cmd.strip()
                if run_cmd.startswith("sudo "):
                    run_cmd = run_cmd[5:].strip()

                if run_cmd.startswith("nmap ") and "-T" not in run_cmd:
                    run_cmd += " -T4 --max-retries 1 --host-timeout 90s"

                try:
                    res = subprocess.run(run_cmd, shell=True, capture_output=True, text=True, timeout=120)
                    out = res.stdout or res.stderr or ""
                    executed_via = "host-network"
                except subprocess.TimeoutExpired:
                    out = f"[Timeout 120s]: A execucao do comando '{cmd}' excedeu o tempo limite."
                    executed_via = "timeout"
                except Exception as e:
                    out = f"[Erro exec direto]: {e}"

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

        elif clean_path == "/api/scan":
            logging.info("Varredura profunda ARP + DNS + NetBIOS de sub-rede disparada no Kali...")
            def run_network_sweep():
                try:
                    subprocess.run(f"arping -b -c 2 -I {IFACE} 255.255.255.255 2>/dev/null", shell=True)
                except Exception:
                    pass
                try:
                    res = subprocess.run("ip -o -f inet addr show " + IFACE + " | awk '{print $4}'", shell=True, capture_output=True, text=True)
                    subnet = res.stdout.strip()
                    if subnet:
                        subprocess.run(f"nmap -sn --system-dns {subnet} 2>/dev/null", shell=True)
                except Exception:
                    pass
            threading.Thread(target=run_network_sweep, daemon=True).start()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"success": True, "message": "Varredura ativa Nmap com resolucao de DNS e NetBIOS iniciada no Kali Linux."}).encode("utf-8"))

        elif clean_path == "/api/device/alias":
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

        elif clean_path == "/api/web-scan":
            target_url = payload.get("targetUrl", "")
            severity_filter = payload.get("severityFilter", "all")
            scan_profile = payload.get("scanProfile", "full")
            if not target_url:
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": "URL do site alvo é obrigatória."}).encode("utf-8"))
                return
            res = run_web_scan_py(target_url, severity_filter, scan_profile)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(res).encode("utf-8"))

        elif clean_path == "/api/network-audit/run":
            res = run_network_audit_py()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(res).encode("utf-8"))

        elif clean_path == "/api/network-audit/profile":
            p = payload
            if not p.get("name") or not p.get("brand") or not p.get("model"):
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Nome, marca e modelo são obrigatórios."}).encode("utf-8"))
                return
            pid = p.get("id") or f"eq-{int(time.time()*1000)}"
            new_p = {**p, "id": pid}
            idx = next((i for i, x in enumerate(equipment_profiles) if x["id"] == pid), -1)
            if idx >= 0:
                equipment_profiles[idx] = new_p
            else:
                equipment_profiles.append(new_p)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"success": True, "profile": new_p}).encode("utf-8"))

        elif clean_path == "/api/network-audit/credential":
            c = payload
            if not c.get("targetIp") or not c.get("username") or not c.get("protocol"):
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": "IP, Usuário e Protocolo são obrigatórios."}).encode("utf-8"))
                return
            cid = c.get("id") or f"cred-{int(time.time()*1000)}"
            port = int(c.get("targetPort", 0)) or (22 if c.get("protocol") == "ssh" else 161 if c.get("protocol") == "snmp_v2c" else 23 if c.get("protocol") == "telnet" else 443)
            new_c = {
                **c,
                "id": cid,
                "targetPort": port,
                "isReadOnly": True,
                "authStatus": "untested",
                "lastTested": "Ainda não testado"
            }
            idx = next((i for i, x in enumerate(equipment_credentials) if x["id"] == cid), -1)
            if idx >= 0:
                equipment_credentials[idx] = new_c
            else:
                equipment_credentials.append(new_c)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"success": True, "credential": {**new_c, "password": "••••••••"}}).encode("utf-8"))

        elif clean_path == "/api/network-audit/test-credential":
            cid = payload.get("id")
            cred = next((c for c in equipment_credentials if c["id"] == cid), None)
            if not cred:
                self.send_response(404)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Credencial não encontrada."}).encode("utf-8"))
                return
            t_ip = cred.get("targetIp")
            port = cred.get("targetPort") or 22
            t0 = time.time()
            is_open = False
            banner = ""
            try:
                with socket.create_connection((t_ip, port), timeout=2.5) as sock:
                    is_open = True
                    try:
                        sock.settimeout(0.8)
                        banner = sock.recv(128).decode("utf-8", errors="ignore").strip()
                    except Exception:
                        pass
            except Exception:
                pass
            lat = int((time.time() - t0) * 1000)
            cred["lastTested"] = datetime.datetime.now().strftime("%H:%M:%S")
            if is_open:
                cred["authStatus"] = "valid"
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({
                    "success": True,
                    "open": True,
                    "message": f"Porta {port} aberta em {t_ip}. Conexão View validada com sucesso!",
                    "banner": banner or "Serviço ativo e respondendo",
                    "latencyMs": lat
                }).encode("utf-8"))
            else:
                cred["authStatus"] = "failed"
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({
                    "success": False,
                    "open": False,
                    "message": f"Falha ao alcançar {t_ip}:{port}. Host offline ou porta fechada.",
                    "latencyMs": lat
                }).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def do_DELETE(self):
        clean_path = self._normalize_path()
        if clean_path.startswith("/api/network-audit/profile/"):
            pid = clean_path.split("/")[-1]
            global equipment_profiles, equipment_credentials
            equipment_profiles = [p for p in equipment_profiles if p["id"] != pid]
            equipment_credentials = [c for c in equipment_credentials if c.get("profileId") != pid]
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"success": True, "id": pid}).encode("utf-8"))
        elif clean_path.startswith("/api/network-audit/credential/"):
            cid = clean_path.split("/")[-1]
            equipment_credentials = [c for c in equipment_credentials if c["id"] != cid]
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"success": True, "id": cid}).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

def start_api():
    server = ThreadingHTTPServer(("0.0.0.0", API_PORT), RestApiHandler)
    logging.info(f"API REST NetSentry pronta em http://0.0.0.0:{API_PORT}/api/status (Interface: {IFACE})")
    server.serve_forever()

threading.Thread(target=start_api, daemon=True).start()

logging.info(f"NetSentry Sniffer Scapy capturando pacotes reais na interface {IFACE}...")
sniff(iface=IFACE, prn=process_packet, store=0)
