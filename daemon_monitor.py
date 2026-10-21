#!/usr/bin/env python3
# ==============================================================================
# NetSentry SOC - Daemon Autônomo com API REST & Sniffer Scapy para Kali Linux
# ==============================================================================
import os, sys, time, subprocess, logging, json, threading
from collections import defaultdict, deque
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
import psycopg2
from scapy.all import sniff, ARP, IP, TCP, UDP, DNS, Ether

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

conn = None
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

def record_device(ip, mac, rx=0, tx=0):
    if not ip or not mac or ip.startswith("127.") or ip == "0.0.0.0" or ip == "255.255.255.255":
        return
    dev_id = f"dev-{mac.replace(':', '').lower()}"
    if conn:
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO network_devices (id, ip, mac, rx_bytes, tx_bytes, last_seen, is_online)
                    VALUES (%s, %s, %s, %s, %s, CURRENT_TIMESTAMP, TRUE)
                    ON CONFLICT (mac) DO UPDATE 
                    SET ip = EXCLUDED.ip, rx_bytes = network_devices.rx_bytes + EXCLUDED.rx_bytes,
                        tx_bytes = network_devices.tx_bytes + EXCLUDED.tx_bytes,
                        last_seen = CURRENT_TIMESTAMP, is_online = TRUE;
                """, (dev_id, ip, mac, rx, tx))
        except Exception:
            pass

def register_threat(title, category, severity, src_ip, src_mac, protocol, details, mit_cmd):
    logging.warning(f"AMEACA DETECTADA: [{severity.upper()}] {title} de {src_ip} ({src_mac})")
    applied = False
    if AUTO_MITIGATE and mit_cmd:
        try:
            logging.info(f"Executando mitigacao autonoma no kernel: {mit_cmd}")
            subprocess.run(mit_cmd, shell=True, capture_output=True, timeout=10)
            applied = True
            metrics["threats_neutralized"] += 1
        except Exception as e:
            logging.error(f"Falha ao executar mitigacao: {e}")

    if conn:
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO threat_alerts (title, category, severity, source_ip, source_mac, protocol, details, mitigation_command, applied)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s);
                """, (title, category, severity, src_ip, src_mac, protocol, details, mit_cmd, applied))
        except Exception:
            pass

def process_packet(pkt):
    metrics["total_packets"] += 1
    pkt_len = len(pkt)
    now = time.time()

    # 1. ARP Spoofing Detection
    if pkt.haslayer(ARP):
        arp = pkt[ARP]
        sender_ip = arp.psrc
        sender_mac = arp.hwsrc
        if arp.op in (1, 2):
            record_device(sender_ip, sender_mac, rx=pkt_len)
            if sender_ip in arp_cache:
                known_mac = arp_cache[sender_ip]
                if known_mac != sender_mac:
                    mit_cmd = f"iptables -I INPUT -m mac --mac-source {sender_mac} -j DROP"
                    register_threat(
                        "ARP Poisoning / Spoofing de Gateway Detectado",
                        "arp_poisoning",
                        "critical",
                        sender_ip,
                        sender_mac,
                        "ARP",
                        f"IP {sender_ip} reivindicado por novo MAC {sender_mac} (MAC legitimo anterior: {known_mac}). Tentativa de MITM.",
                        mit_cmd
                    )
            else:
                arp_cache[sender_ip] = sender_mac

        recent_traffic.append({
            "id": f"fl-{now}-{metrics['total_packets']}",
            "timestamp": time.strftime("%H:%M:%S"),
            "protocol": "ARP",
            "srcIp": sender_ip,
            "dstIp": arp.pdst,
            "packetLength": pkt_len,
            "info": f"ARP {'Request' if arp.op == 1 else 'Reply'} from {sender_mac}"
        })
        return

    # 2. IP Packets Inspection
    if pkt.haslayer(IP):
        ip = pkt[IP]
        src_ip = ip.src
        dst_ip = ip.dst
        src_mac = pkt[Ether].src if pkt.haslayer(Ether) else ""
        record_device(src_ip, src_mac, tx=pkt_len)

        # SYN Port Scan Detection
        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            if tcp.flags == "S":
                window = syn_tracker[src_ip]
                window.append(now)
                while window and now - window[0] > 3.0:
                    window.popleft()
                if len(window) > 15:
                    mit_cmd = f"iptables -I INPUT -s {src_ip} -p tcp --syn -j DROP"
                    register_threat(
                        "Varredura Rapida de Portas TCP SYN (Nmap Stealth Scan)",
                        "port_scan",
                        "high",
                        src_ip,
                        src_mac,
                        "TCP",
                        f"{len(window)} pacotes TCP SYN recebidos em menos de 3s vindos de {src_ip}.",
                        mit_cmd
                    )
                    window.clear()

            recent_traffic.append({
                "id": f"fl-{now}-{metrics['total_packets']}",
                "timestamp": time.strftime("%H:%M:%S"),
                "protocol": "TCP",
                "srcIp": src_ip,
                "dstIp": dst_ip,
                "packetLength": pkt_len,
                "info": f"TCP {tcp.sport} -> {tcp.dport} [{tcp.flags}]"
            })

        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            if pkt.haslayer(DNS):
                recent_traffic.append({
                    "id": f"fl-{now}-{metrics['total_packets']}",
                    "timestamp": time.strftime("%H:%M:%S"),
                    "protocol": "DNS",
                    "srcIp": src_ip,
                    "dstIp": dst_ip,
                    "packetLength": pkt_len,
                    "info": f"DNS Query UDP 53"
                })

class RestApiHandler(BaseHTTPRequestHandler):
    def end_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
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
                "interface": IFACE,
                "totalPackets": metrics["total_packets"],
                "pps": metrics["pps"],
                "bandwidthKbps": int((metrics["bytes_last_sec"] * 8) / 1024),
                "totalThreatsNeutralized": metrics["threats_neutralized"],
                "autonomousMode": AUTO_MITIGATE,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
            }
            self.wfile.write(json.dumps(data).encode("utf-8"))

        elif self.path == "/api/devices":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            devices = []
            if conn:
                try:
                    with conn.cursor() as cur:
                        cur.execute("SELECT id, ip, mac, hostname, vendor, device_type, trust_level, threat_score, rx_bytes, tx_bytes, is_online FROM network_devices ORDER BY last_seen DESC;")
                        for r in cur.fetchall():
                            devices.append({
                                "id": r[0], "ip": r[1], "mac": r[2], "hostname": r[3],
                                "vendor": r[4], "deviceType": r[5], "trustLevel": r[6],
                                "threatScore": r[7], "rxBytes": r[8], "txBytes": r[9],
                                "isOnline": r[10], "openPorts": []
                            })
                except Exception:
                    pass
            self.wfile.write(json.dumps(devices).encode("utf-8"))

        elif self.path == "/api/alerts":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            alerts = []
            if conn:
                try:
                    with conn.cursor() as cur:
                        cur.execute("SELECT id, timestamp, title, category, severity, source_ip, source_mac, mitigation_command, applied, details FROM threat_alerts ORDER BY timestamp DESC LIMIT 50;")
                        for r in cur.fetchall():
                            alerts.append({
                                "id": str(r[0]), "timestamp": str(r[1]), "title": r[2],
                                "category": r[3], "severity": r[4], "sourceIp": r[5],
                                "sourceMac": r[6], "details": r[9], "confidence": 95,
                                "status": "mitigated" if r[8] else "active",
                                "playbook": {
                                    "id": f"pb-{r[0]}",
                                    "actionName": "Regra Netfilter",
                                    "description": "Descarte de pacotes maliciosos no kernel do Kali Linux.",
                                    "severity": r[4],
                                    "iptablesCommand": r[7] or "iptables -A INPUT -j DROP",
                                    "kaliToolCommand": f"nmap -sV -sC -O -Pn {r[5]}",
                                    "automatedAvailable": True,
                                    "applied": bool(r[8]),
                                    "rollbackCommand": (r[7] or "").replace("-I INPUT", "-D INPUT").replace("-A INPUT", "-D INPUT")
                                }
                            })
                except Exception:
                    pass
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
                    res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
                    out = res.stdout or res.stderr
                except Exception as e:
                    out = f"[Erro]: {e}"
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
                    out = f"[Timeout 120s]: A execucao de '{cmd}' excedeu o tempo limite."
                    executed_via = "timeout"
                except Exception as e:
                    out = f"[Erro exec]: {e}"

                if (not out.strip() or "[Erro" in out) and executed_via != "timeout":
                    try:
                        res = subprocess.run(f"nsenter -t 1 -m -u -i -n -p -- bash -c '{run_cmd}'", shell=True, capture_output=True, text=True, timeout=60)
                        if res.stdout or res.stderr:
                            out = res.stdout or res.stderr
                            executed_via = "nsenter-host"
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
            logging.info("Varredura de sub-rede disparada...")
            def run_network_sweep():
                try:
                    subprocess.run(f"arping -b -c 2 -I {IFACE} 255.255.255.255 2>/dev/null", shell=True)
                except Exception:
                    pass
                try:
                    res = subprocess.run("ip -o -f inet addr show " + IFACE + " | awk '{print $4}'", shell=True, capture_output=True, text=True)
                    subnet = res.stdout.strip()
                    if subnet:
                        subprocess.run(f"nmap -sn -n --send-ip {subnet} 2>/dev/null", shell=True)
                except Exception:
                    pass
            threading.Thread(target=run_network_sweep, daemon=True).start()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"success": True, "message": "Varredura iniciada no Kali."}).encode("utf-8"))
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
