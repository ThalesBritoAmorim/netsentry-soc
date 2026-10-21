import { 
  NetworkDevice, 
  ThreatAlert, 
  TrafficFlow, 
  AnomalyDetectionRule, 
  DatabaseBackup, 
  UserAccount, 
  AuditLogEntry,
  SystemMetrics
} from '../types';

export const INITIAL_SYSTEM_METRICS: SystemMetrics = {
  sniffingInterface: 'eth0 (promisc)',
  promiscuousMode: true,
  pythonDaemonState: 'running',
  postgresState: 'connected',
  portainerStackName: 'netsentry-production',
  pps: 142,
  bandwidthKbps: 845.2,
  totalPackets: 894210,
  totalThreatsNeutralized: 18,
  autonomousMode: true,
};

export const INITIAL_DEVICES: NetworkDevice[] = [
  {
    id: 'dev-1',
    ip: '192.168.1.1',
    mac: 'e4:5d:51:78:22:01',
    hostname: 'gw-core-edge.local',
    vendor: 'Ubiquiti Networks',
    deviceType: 'gateway',
    trustLevel: 'trusted',
    openPorts: [
      { port: 53, service: 'dns', risk: 'low' },
      { port: 80, service: 'http', risk: 'medium' },
      { port: 443, service: 'https', risk: 'low' }
    ],
    rxBytes: 421890000,
    txBytes: 310500000,
    packetCount: 384000,
    threatScore: 4,
    firstSeen: '2026-10-01 00:00:00',
    lastSeen: 'Agora',
    isOnline: true,
    notes: 'Gateway central de borda e servidor DHCP corporativo.'
  },
  {
    id: 'dev-2',
    ip: '192.168.1.50',
    mac: '00:0c:29:ab:cd:ef',
    hostname: 'kali-soc-node01',
    vendor: 'VMware / Intel Corp.',
    deviceType: 'kali_node',
    trustLevel: 'trusted',
    openPorts: [
      { port: 22, service: 'ssh', version: 'OpenSSH 9.6p1', risk: 'low' },
      { port: 9000, service: 'portainer', risk: 'low' },
      { port: 3000, service: 'netsentry-ui', risk: 'low' },
      { port: 5432, service: 'postgresql', risk: 'medium' }
    ],
    rxBytes: 89200000,
    txBytes: 67300000,
    packetCount: 198000,
    threatScore: 0,
    firstSeen: '2026-10-01 00:00:00',
    lastSeen: 'Agora',
    isOnline: true,
    notes: 'Host Kali Linux executando Portainer CE e o NetSentry Daemon em modo promíscuo.'
  },
  {
    id: 'dev-3',
    ip: '192.168.1.189',
    mac: 'b8:27:eb:99:34:12',
    hostname: 'cam-deposito-norte',
    vendor: 'Dahua / Raspberry Pi Foundation',
    deviceType: 'iot',
    trustLevel: 'unverified',
    openPorts: [
      { port: 23, service: 'telnet', risk: 'critical', cve: 'CVE-2023-41266' },
      { port: 80, service: 'http', risk: 'medium' },
      { port: 554, service: 'rtsp', risk: 'low' }
    ],
    rxBytes: 21400000,
    txBytes: 94000000,
    packetCount: 142000,
    threatScore: 78,
    firstSeen: '2026-10-14 09:22:10',
    lastSeen: '1 min atrás',
    isOnline: true,
    notes: 'Câmera IP IoT com porta Telnet 23 aberta para a rede interna. Potencial vetor de ataque.'
  },
  {
    id: 'dev-4',
    ip: '192.168.1.200',
    mac: '00:11:32:89:a4:2b',
    hostname: 'synology-nas-backup',
    vendor: 'Synology Inc.',
    deviceType: 'server',
    trustLevel: 'trusted',
    openPorts: [
      { port: 445, service: 'microsoft-ds (SMB)', risk: 'medium' },
      { port: 2049, service: 'nfs', risk: 'medium' },
      { port: 5001, service: 'https-dsm', risk: 'low' }
    ],
    rxBytes: 745000000,
    txBytes: 89000000,
    packetCount: 512000,
    threatScore: 12,
    firstSeen: '2026-10-02 08:00:00',
    lastSeen: 'Agora',
    isOnline: true,
    notes: 'Storage NAS de armazenamento de backups do PostgreSQL e imagens de sistema.'
  },
  {
    id: 'dev-5',
    ip: '192.168.1.105',
    mac: '3c:22:fb:44:aa:55',
    hostname: 'ws-dev-eng04',
    vendor: 'Dell Inc.',
    deviceType: 'workstation',
    trustLevel: 'trusted',
    openPorts: [
      { port: 22, service: 'ssh', risk: 'low' },
      { port: 8080, service: 'http-proxy', risk: 'low' }
    ],
    rxBytes: 15400000,
    txBytes: 8900000,
    packetCount: 42000,
    threatScore: 8,
    firstSeen: '2026-10-05 07:45:00',
    lastSeen: '3 mins atrás',
    isOnline: true,
    notes: 'Estação de trabalho da engenharia de software.'
  },
  {
    id: 'dev-6',
    ip: '192.168.1.240',
    mac: '52:54:00:fa:8c:19',
    hostname: 'unknown-host-240',
    vendor: 'QEMU / Virtual Interface',
    deviceType: 'unknown',
    trustLevel: 'quarantined',
    openPorts: [
      { port: 4444, service: 'metasploit-listener', risk: 'critical' },
      { port: 8888, service: 'http-c2', risk: 'high' }
    ],
    rxBytes: 12400000,
    txBytes: 45800000,
    packetCount: 89000,
    threatScore: 94,
    firstSeen: '2026-10-18 10:15:33',
    lastSeen: 'Agora',
    isOnline: true,
    notes: 'Dispositivo recém-conectado disparando varreduras SYN e requisições ARP inconsistentes.'
  }
];

export const INITIAL_ALERTS: ThreatAlert[] = [
  {
    id: 'alt-01',
    timestamp: '2026-10-18 12:21:40',
    title: 'ARP Poisoning Detectado (Tentativa de MITM)',
    category: 'arp_poisoning',
    severity: 'critical',
    sourceIp: '192.168.1.240',
    sourceMac: '52:54:00:fa:8c:19',
    targetIp: '192.168.1.1',
    protocol: 'ARP',
    confidence: 97,
    mitreAttack: 'T1557.002 - Adversary-in-the-Middle: ARP Poisoning',
    details: 'Dispositivo com MAC 52:54:00:fa:8c:19 enviou 320 pacotes Gratuitous ARP reivindicando a titularidade do IP do Gateway (192.168.1.1). Tentativa de interceptar tráfego da sub-rede.',
    status: 'active',
    playbook: {
      id: 'pb-01',
      actionName: 'Isolamento de Camada 2 & Bloqueio IPTables',
      description: 'Dropar pacotes do atacante via netfilter do kernel Linux e limpar cache ARP estático do Gateway.',
      severity: 'critical',
      iptablesCommand: 'sudo iptables -I INPUT -m mac --mac-source 52:54:00:fa:8c:19 -j DROP && sudo iptables -I FORWARD -m mac --mac-source 52:54:00:fa:8c:19 -j DROP',
      kaliToolCommand: 'sudo arp -d 192.168.1.240 && sudo arpspoof -i eth0 -t 192.168.1.1 192.168.1.240 -r',
      suricataRule: 'drop arp 52:54:00:fa:8c:19 any -> any any (msg:"NETSENTRY Autodetect ARP Poisoning"; sid:9000001; rev:1;)',
      automatedAvailable: true,
      applied: false,
      rollbackCommand: 'sudo iptables -D INPUT -m mac --mac-source 52:54:00:fa:8c:19 -j DROP && sudo iptables -D FORWARD -m mac --mac-source 52:54:00:fa:8c:19 -j DROP'
    }
  },
  {
    id: 'alt-02',
    timestamp: '2026-10-18 12:14:05',
    title: 'Varredura Rápida de Portas SYN (Nmap Stealth Scan)',
    category: 'port_scan',
    severity: 'high',
    sourceIp: '192.168.1.240',
    sourceMac: '52:54:00:fa:8c:19',
    targetIp: '192.168.1.50',
    protocol: 'TCP',
    confidence: 94,
    mitreAttack: 'T1046 - Network Service Discovery',
    details: 'Origem atingiu mais de 128 portas distintas no host Kali em janela inferior a 2.4 segundos com pacotes TCP SYN sem conclusão de handshake (varredura stealth).',
    status: 'active',
    playbook: {
      id: 'pb-02',
      actionName: 'Rate-Limit e Blackhole do IP de Origem',
      description: 'Aplicar regra blackhole na tabela de roteamento do kernel ou dropar tráfego SYN recorrente.',
      severity: 'high',
      iptablesCommand: 'sudo iptables -A INPUT -s 192.168.1.240 -p tcp --tcp-flags SYN,ACK,FIN,RST SYN -j DROP',
      kaliToolCommand: 'sudo ip route add blackhole 192.168.1.240/32 && sudo fail2ban-client set netsentry-jail banip 192.168.1.240',
      suricataRule: 'alert tcp 192.168.1.240 any -> 192.168.1.0/24 any (flags:S; threshold:type threshold, track by_src, count 30, seconds 5; msg:"NETSENTRY Port Sweep Detected"; sid:9000002; rev:1;)',
      automatedAvailable: true,
      applied: false,
      rollbackCommand: 'sudo iptables -D INPUT -s 192.168.1.240 -p tcp --tcp-flags SYN,ACK,FIN,RST SYN -j DROP && sudo ip route del blackhole 192.168.1.240/32'
    }
  },
  {
    id: 'alt-03',
    timestamp: '2026-10-18 11:58:20',
    title: 'Tunelamento DNS Suspeito (Exfiltração de Dados)',
    category: 'dns_tunneling',
    severity: 'high',
    sourceIp: '192.168.1.189',
    targetIp: '198.51.100.44',
    protocol: 'DNS',
    confidence: 89,
    mitreAttack: 'T1071.004 - Application Layer Protocol: DNS',
    details: 'Requisições DNS recorrentes contendo subdomínios de alta entropia Shannon (4.65 bits) e comprimento superior a 52 caracteres (ex: "a8f3c7e91244.sync-update.attacker-ns.cc").',
    status: 'investigating',
    playbook: {
      id: 'pb-03',
      actionName: 'Bloqueio de Servidor DNS Malicioso & Quarentena IoT',
      description: 'Redirecionar tráfego DNS da câmera para o resolver local seguro e bloquear resolução do domínio de C2.',
      severity: 'high',
      iptablesCommand: 'sudo iptables -t nat -A PREROUTING -s 192.168.1.189 -p udp --dport 53 -j DNAT --to-destination 192.168.1.1:53',
      kaliToolCommand: 'echo "0.0.0.0 attacker-ns.cc" | sudo tee -a /etc/hosts && sudo systemctl reload dnsmasq',
      automatedAvailable: true,
      applied: false,
      rollbackCommand: 'sudo iptables -t nat -D PREROUTING -s 192.168.1.189 -p udp --dport 53 -j DNAT --to-destination 192.168.1.1:53'
    }
  },
  {
    id: 'alt-04',
    timestamp: '2026-10-18 10:45:12',
    title: 'Dispositivo Desconhecido Conectado (Rogue Device)',
    category: 'rogue_device',
    severity: 'medium',
    sourceIp: '192.168.1.240',
    sourceMac: '52:54:00:fa:8c:19',
    targetIp: '255.255.255.255',
    protocol: 'ARP/DHCP',
    confidence: 100,
    mitreAttack: 'T1200 - Hardware Additions',
    details: 'Novo endereço MAC identificado na rede que não consta na lista de dispositivos autorizados no banco PostgreSQL.',
    status: 'mitigated',
    playbook: {
      id: 'pb-04',
      actionName: 'Adicionar à Quarentena e Notificar Administrador',
      description: 'Isolar tráfego da LAN até auditoria e aprovação manual de confiança pelo operador.',
      severity: 'medium',
      iptablesCommand: 'sudo iptables -A FORWARD -m mac --mac-source 52:54:00:fa:8c:19 -j DROP',
      kaliToolCommand: 'nmap -sV -sC -O -Pn 192.168.1.240 -oN /var/log/netsentry/scan_rogue_240.txt',
      automatedAvailable: true,
      applied: true,
      appliedAt: '2026-10-18 10:46:00',
      rollbackCommand: 'sudo iptables -D FORWARD -m mac --mac-source 52:54:00:fa:8c:19 -j DROP'
    }
  }
];

export const INITIAL_TRAFFIC_FLOWS: TrafficFlow[] = [
  {
    id: 'fl-101',
    timestamp: '12:27:55',
    protocol: 'ARP',
    srcIp: '192.168.1.240',
    dstIp: '192.168.1.1',
    packetLength: 42,
    flags: 'Gratuitous',
    info: 'Who has 192.168.1.1? Tell 192.168.1.240 (Spoof Flagged)',
    isSuspicious: true,
    anomalyReason: 'Gratuitous ARP mismatch com MAC da tabela autorizada'
  },
  {
    id: 'fl-102',
    timestamp: '12:27:54',
    protocol: 'TCP',
    srcIp: '192.168.1.240',
    srcPort: 48922,
    dstIp: '192.168.1.50',
    dstPort: 445,
    packetLength: 60,
    flags: 'SYN',
    info: 'TCP Connection Attempt -> 445 (SMB) [Closed]',
    isSuspicious: true,
    anomalyReason: 'Sequência rápida de SYN scan'
  },
  {
    id: 'fl-103',
    timestamp: '12:27:53',
    protocol: 'TCP',
    srcIp: '192.168.1.240',
    srcPort: 48923,
    dstIp: '192.168.1.50',
    dstPort: 3389,
    packetLength: 60,
    flags: 'SYN',
    info: 'TCP Connection Attempt -> 3389 (RDP) [Closed]',
    isSuspicious: true,
    anomalyReason: 'Sequência rápida de SYN scan'
  },
  {
    id: 'fl-104',
    timestamp: '12:27:50',
    protocol: 'DNS',
    srcIp: '192.168.1.189',
    srcPort: 54112,
    dstIp: '198.51.100.44',
    dstPort: 53,
    packetLength: 148,
    flags: 'Standard query',
    info: 'A 9f8a11bc3e.exfil.attacker-ns.cc (Entropy: 4.7)',
    isSuspicious: true,
    anomalyReason: 'Alta entropia e padrão de tunelamento DNS'
  },
  {
    id: 'fl-105',
    timestamp: '12:27:49',
    protocol: 'TLS',
    srcIp: '192.168.1.105',
    srcPort: 51240,
    dstIp: '142.250.190.46',
    dstPort: 443,
    packetLength: 1240,
    flags: 'Application Data',
    info: 'TLSv1.3 Encrypted Session (Google APIs)',
    isSuspicious: false
  },
  {
    id: 'fl-106',
    timestamp: '12:27:48',
    protocol: 'TCP',
    srcIp: '192.168.1.50',
    srcPort: 5432,
    dstIp: '192.168.1.50',
    dstPort: 41200,
    packetLength: 512,
    flags: 'ACK, PSH',
    info: 'PostgreSQL Query Transaction (SELECT alerts, status FROM soc)',
    isSuspicious: false
  },
  {
    id: 'fl-107',
    timestamp: '12:27:45',
    protocol: 'HTTP',
    srcIp: '192.168.1.105',
    srcPort: 52190,
    dstIp: '192.168.1.50',
    dstPort: 9000,
    packetLength: 820,
    flags: 'GET',
    info: 'Portainer API /api/endpoints/1/docker/containers/json',
    isSuspicious: false
  },
  {
    id: 'fl-108',
    timestamp: '12:27:42',
    protocol: 'ICMP',
    srcIp: '192.168.1.50',
    dstIp: '192.168.1.1',
    packetLength: 64,
    flags: 'Echo (ping) request',
    info: 'NetSentry Keep-alive latency check (0.84ms)',
    isSuspicious: false
  }
];

export const INITIAL_ANOMALY_RULES: AnomalyDetectionRule[] = [
  {
    id: 'rule-arp-01',
    name: 'Detecção de Conflito de IP e Spoofing ARP',
    category: 'arp_poisoning',
    description: 'Dispara quando o mesmo IP envia pacotes com MAC diferente do registrado no banco Postgres dentro de 10s.',
    metric: 'ARP Mismatch / Segundo',
    threshold: 3,
    timeWindowSeconds: 5,
    enabled: true,
    autoMitigate: true,
    triggersCount: 4
  },
  {
    id: 'rule-scan-02',
    name: 'Varredura Rápida de Portas TCP SYN',
    category: 'port_scan',
    description: 'Identifica IPs enviando requisições SYN para mais de N portas fechadas sem responder ao ACK.',
    metric: 'Portas Distintas / Segundo',
    threshold: 15,
    timeWindowSeconds: 3,
    enabled: true,
    autoMitigate: true,
    triggersCount: 8
  },
  {
    id: 'rule-dns-03',
    name: 'Análise de Entropia de Subdomínios DNS',
    category: 'dns_tunneling',
    description: 'Calcula o valor de Shannon de cada query DNS. Dispara se tamanho > 35 caracteres e entropia > 4.2 bits.',
    metric: 'Shannon Entropy Bits',
    threshold: 4.2,
    timeWindowSeconds: 10,
    enabled: true,
    autoMitigate: false,
    triggersCount: 2
  },
  {
    id: 'rule-ddos-04',
    name: 'Surto Volumétrico de Pacotes (SYN Flood)',
    category: 'ddos_flood',
    description: 'Detecta aumento anômalo súbito de pacotes por segundo contra um único endereço IP da rede interna.',
    metric: 'Pacotes / Segundo (PPS)',
    threshold: 600,
    timeWindowSeconds: 2,
    enabled: true,
    autoMitigate: true,
    triggersCount: 1
  },
  {
    id: 'rule-rogue-05',
    name: 'Dispositivo Não Autorizado na Sub-rede',
    category: 'rogue_device',
    description: 'Alerta imediatamente quando um novo endereço MAC transmite tráfego e não existe na whitelist do Postgres.',
    metric: 'Novo MAC não catalogado',
    threshold: 1,
    timeWindowSeconds: 1,
    enabled: true,
    autoMitigate: false,
    triggersCount: 3
  }
];

export const INITIAL_BACKUPS: DatabaseBackup[] = [
  {
    id: 'bk-20261018-0600',
    filename: 'netsentry_db_backup_20261018_060000.sql.gz',
    sizeMb: 14.8,
    createdAt: '2026-10-18 06:00:00',
    type: 'scheduled',
    status: 'verified',
    tableRowsCount: 148200
  },
  {
    id: 'bk-20261017-0600',
    filename: 'netsentry_db_backup_20261017_060000.sql.gz',
    sizeMb: 13.9,
    createdAt: '2026-10-17 06:00:00',
    type: 'scheduled',
    status: 'verified',
    tableRowsCount: 139100
  },
  {
    id: 'bk-20261016-1830',
    filename: 'netsentry_db_manual_pre_update.sql.gz',
    sizeMb: 12.4,
    createdAt: '2026-10-16 18:30:15',
    type: 'manual',
    status: 'verified',
    tableRowsCount: 125400
  }
];

export const INITIAL_USERS: UserAccount[] = [
  {
    id: 'usr-1',
    name: 'Thales Brito Amorim',
    email: 'thalesbritoamorim89@gmail.com',
    role: 'admin',
    lastActive: 'Agora (Sessão Atual)',
    twoFactorEnabled: true
  },
  {
    id: 'usr-2',
    name: 'SecOps Analyst',
    email: 'analyst@soc.internal',
    role: 'analyst',
    lastActive: '12 minutos atrás',
    twoFactorEnabled: true
  },
  {
    id: 'usr-3',
    name: 'Auditor Externo',
    email: 'auditor@compliance.org',
    role: 'auditor',
    lastActive: 'Ontem às 17:40',
    twoFactorEnabled: false
  }
];

export const INITIAL_AUDIT_LOGS: AuditLogEntry[] = [
  {
    id: 'aud-109',
    timestamp: '2026-10-18 12:21:55',
    operator: 'Autonomous Engine (NetSentry)',
    action: 'Geração de Playbook de Mitigação ARP',
    target: '52:54:00:fa:8c:19',
    status: 'success',
    ipAddress: '192.168.1.50'
  },
  {
    id: 'aud-108',
    timestamp: '2026-10-18 10:46:00',
    operator: 'thalesbritoamorim89@gmail.com',
    action: 'Execução de Quarentena de Dispositivo',
    target: '192.168.1.240',
    status: 'success',
    ipAddress: '192.168.1.105'
  },
  {
    id: 'aud-107',
    timestamp: '2026-10-18 06:00:02',
    operator: 'Portainer Cron Service',
    action: 'Backup Automático PostgreSQL (pg_dump)',
    target: 'database: netsentry_db',
    status: 'success',
    ipAddress: '127.0.0.1'
  },
  {
    id: 'aud-106',
    timestamp: '2026-10-17 19:15:20',
    operator: 'thalesbritoamorim89@gmail.com',
    action: 'Ativação do Modo Autônomo com Mitigação Automática',
    target: 'Engine Heurístico v2.4',
    status: 'success',
    ipAddress: '192.168.1.105'
  }
];
