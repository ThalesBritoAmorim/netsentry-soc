export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type ThreatCategory = 
  | 'arp_poisoning'
  | 'port_scan'
  | 'dns_tunneling'
  | 'ddos_flood'
  | 'rogue_device'
  | 'brute_force'
  | 'c2_beaconing'
  | 'anomalous_outbound';

export type AlertStatus = 'active' | 'investigating' | 'mitigated' | 'whitelisted';

export type DeviceTrustLevel = 'trusted' | 'unverified' | 'quarantined' | 'blocked';

export type DeviceType = 'gateway' | 'kali_node' | 'server' | 'workstation' | 'iot' | 'unknown';

export interface OpenPort {
  port: number;
  service: string;
  version?: string;
  risk: 'low' | 'medium' | 'high' | 'critical';
  cve?: string;
}

export interface NetworkDevice {
  id: string;
  ip: string;
  mac: string;
  hostname: string;
  vendor: string;
  deviceType: DeviceType;
  trustLevel: DeviceTrustLevel;
  openPorts: OpenPort[];
  rxBytes: number;
  txBytes: number;
  packetCount: number;
  threatScore: number; // 0 to 100
  firstSeen: string;
  lastSeen: string;
  isOnline: boolean;
  notes?: string;
}

export interface MitigationPlaybook {
  id: string;
  actionName: string;
  description: string;
  severity: SeverityLevel;
  iptablesCommand: string;
  kaliToolCommand: string;
  suricataRule?: string;
  automatedAvailable: boolean;
  applied: boolean;
  appliedAt?: string;
  rollbackCommand: string;
}

export interface ThreatAlert {
  id: string;
  timestamp: string;
  title: string;
  category: ThreatCategory;
  severity: SeverityLevel;
  sourceIp: string;
  sourceMac?: string;
  targetIp: string;
  targetPort?: number;
  protocol: string;
  confidence: number; // Percentage 0 - 100
  mitreAttack?: string;
  details: string;
  status: AlertStatus;
  playbook: MitigationPlaybook;
}

export interface TrafficFlow {
  id: string;
  timestamp: string;
  protocol: 'TCP' | 'UDP' | 'ICMP' | 'DNS' | 'ARP' | 'HTTP' | 'TLS';
  srcIp: string;
  srcPort?: number;
  dstIp: string;
  dstPort?: number;
  packetLength: number;
  flags?: string;
  info: string;
  isSuspicious: boolean;
  anomalyReason?: string;
}

export interface AnomalyDetectionRule {
  id: string;
  name: string;
  category: ThreatCategory;
  description: string;
  metric: string;
  threshold: number;
  timeWindowSeconds: number;
  enabled: boolean;
  autoMitigate: boolean;
  triggersCount: number;
}

export interface SecurityReport {
  id: string;
  title: string;
  generatedAt: string;
  author: string;
  period: string;
  summary: string;
  totalAlerts: number;
  criticalAlerts: number;
  mitigatedAlerts: number;
  devicesScanned: number;
  threatScoreAverage: number;
  executiveActionPlan: string[];
}

export interface DatabaseBackup {
  id: string;
  filename: string;
  sizeMb: number;
  createdAt: string;
  type: 'manual' | 'scheduled';
  status: 'healthy' | 'verified';
  tableRowsCount: number;
}

export interface UserAccount {
  id: string;
  name: string;
  email: string;
  role: 'admin' | 'analyst' | 'auditor';
  lastActive: string;
  twoFactorEnabled: boolean;
}

export interface AuditLogEntry {
  id: string;
  timestamp: string;
  operator: string;
  action: string;
  target: string;
  status: 'success' | 'warning' | 'failed';
  ipAddress: string;
}

export interface SystemMetrics {
  sniffingInterface: string;
  promiscuousMode: boolean;
  pythonDaemonState: 'running' | 'idle' | 'stopped';
  postgresState: 'connected' | 'reconnecting' | 'error';
  portainerStackName: string;
  pps: number;
  bandwidthKbps: number;
  totalPackets: number;
  totalThreatsNeutralized: number;
  autonomousMode: boolean;
  isLiveKaliConnected?: boolean;
  kaliHostUrl?: string;
  lastKaliSync?: string;
}

export type AIProviderId = 'gemini' | 'claude' | 'openai' | 'ollama';

export interface AIProviderConfig {
  id: AIProviderId;
  name: string;
  vendor: string;
  type: 'cloud' | 'local';
  defaultModel: string;
  availableModels: string[];
  isConfigured: boolean;
  endpointUrl?: string;
  status: 'ready' | 'offline' | 'checking';
  latencyMs?: number;
  description: string;
}

export interface AISettings {
  activeProvider: AIProviderId;
  selectedModel: string;
  anonymizeNetworkData: boolean;
  strictOfflineMode: boolean;
  ollamaEndpoint: string;
  temperature: number;
}

export interface AnalysisParameters {
  // Detection Thresholds
  ppsFloodThreshold: number;
  portScanThreshold: number;
  dnsEntropyThreshold: number;
  arpSpoofSensitivity: 'strict' | 'moderate' | 'permissive';
  
  // Network Filters & Whitelists
  whitelistedIps: string[];
  protectedPorts: number[];
  monitoredSubnets: string[];
  
  // AI Forensic Parameters
  forensicDetailLevel: 'summary' | 'standard' | 'deep_forensic';
  prioritizeMitre: boolean;
  iptablesRuleType: 'drop' | 'reject' | 'tarpit';
  autoAnonymizeTopology: boolean;
  
  // Response & Mitigation Policies
  autoBlockHighSeverity: boolean;
  blockTtlMinutes: number;
  enableAudioAlerts: boolean;
  enableDesktopBanners: boolean;
}
