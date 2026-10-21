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
  sniffingInterface: 'Aguardando agente Kali...',
  promiscuousMode: true,
  pythonDaemonState: 'idle',
  postgresState: 'connected',
  portainerStackName: 'netsentry-soc',
  pps: 0,
  bandwidthKbps: 0,
  totalPackets: 0,
  totalThreatsNeutralized: 0,
  autonomousMode: true,
};

// 100% REAL: Sem dados fictícios pré-populados. Os dispositivos são descobertos pelo sniffer e tabela ARP.
export const INITIAL_DEVICES: NetworkDevice[] = [];

// 100% REAL: Sem alertas falsos pré-populados. Apenas incidentes reais detectados na rede física.
export const INITIAL_ALERTS: ThreatAlert[] = [];

// 100% REAL: Sem fluxos de tráfego falsos. Apenas pacotes reais capturados pelo Scapy.
export const INITIAL_TRAFFIC_FLOWS: TrafficFlow[] = [];

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
    triggersCount: 0
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
    triggersCount: 0
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
    triggersCount: 0
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
    triggersCount: 0
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
    triggersCount: 0
  }
];

// 100% REAL: Sem backups fictícios. Os backups são gerados a partir do PostgreSQL real via pg_dump.
export const INITIAL_BACKUPS: DatabaseBackup[] = [];

export const INITIAL_USERS: UserAccount[] = [
  {
    id: 'usr-1',
    name: 'Thales Brito Amorim',
    email: 'thalesbritoamorim89@gmail.com',
    role: 'admin',
    lastActive: 'Agora (Sessão Atual)',
    twoFactorEnabled: true
  }
];

// 100% REAL: Registro de auditoria inicial do sensor SOC
export const INITIAL_AUDIT_LOGS: AuditLogEntry[] = [
  {
    id: 'aud-init-01',
    timestamp: 'Inicialização',
    operator: 'sistema@netsentry.local',
    action: 'Sensor NetSentry SOC Inicializado (Aguardando Captura de Pacotes)',
    target: 'Kernel Kali Linux',
    status: 'success',
    ipAddress: '127.0.0.1'
  }
];
