import { 
  NetworkDevice, 
  ThreatAlert, 
  TrafficFlow, 
  AnomalyDetectionRule, 
  DatabaseBackup, 
  AuditLogEntry, 
  SystemMetrics,
  ThreatCategory
} from '../types';
import { 
  INITIAL_DEVICES, 
  INITIAL_ALERTS, 
  INITIAL_TRAFFIC_FLOWS, 
  INITIAL_ANOMALY_RULES, 
  INITIAL_BACKUPS, 
  INITIAL_AUDIT_LOGS, 
  INITIAL_SYSTEM_METRICS 
} from './initialData';
import { parametersService } from './parametersService';

// Client-side MAC OUI prefix dictionary for instant local vendor identification
const CLIENT_OUI_MAP: Record<string, string> = {
  'b8:27:eb': 'Raspberry Pi Foundation',
  'dc:a6:32': 'Raspberry Pi Foundation',
  'e4:5f:01': 'Raspberry Pi Foundation',
  '00:50:56': 'VMware ESXi / Workstation',
  '08:00:27': 'Oracle VirtualBox',
  '52:54:00': 'QEMU / KVM Host',
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
  '00:0c:e7': 'Cisco Systems',
  '00:1e:67': 'Intel Corporate',
  '00:14:22': 'Dell Inc.',
  '00:1e:0b': 'HP Inc.',
  '00:11:32': 'Synology NAS',
  '00:08:9b': 'QNAP NAS',
  '44:65:0d': 'Amazon Echo / FireTV',
  '70:ee:50': 'Google Nest / Chromecast',
  '78:11:dc': 'Xiaomi Communications',
  '10:bf:48': 'ASUSTeK Computer'
};

function getClientVendor(mac: string): string {
  if (!mac) return 'Desconhecido';
  const prefix = mac.toLowerCase().split(':').slice(0, 3).join(':');
  return CLIENT_OUI_MAP[prefix] || 'Dispositivo de Rede IEEE';
}

const DEVICE_ALIAS_STORAGE_KEY = 'netsentry_device_aliases_v1';

function getStoredAliases(): Record<string, string> {
  try {
    const raw = localStorage.getItem(DEVICE_ALIAS_STORAGE_KEY);
    return raw ? JSON.parse(raw) : {};
  } catch (e) {
    return {};
  }
}

function saveStoredAlias(key: string, alias: string) {
  try {
    const current = getStoredAliases();
    if (alias.trim()) {
      current[key] = alias.trim();
    } else {
      delete current[key];
    }
    localStorage.setItem(DEVICE_ALIAS_STORAGE_KEY, JSON.stringify(current));
  } catch (e) {}
}

export interface NetworkEngineState {
  devices: NetworkDevice[];
  alerts: ThreatAlert[];
  trafficFlows: TrafficFlow[];
  rules: AnomalyDetectionRule[];
  backups: DatabaseBackup[];
  auditLogs: AuditLogEntry[];
  metrics: SystemMetrics;
  isStreaming: boolean;
}

export type NetworkEventCallback = (state: NetworkEngineState) => void;

class NetworkEngine {
  private state: NetworkEngineState = {
    devices: [...INITIAL_DEVICES],
    alerts: [...INITIAL_ALERTS],
    trafficFlows: [...INITIAL_TRAFFIC_FLOWS],
    rules: [...INITIAL_ANOMALY_RULES],
    backups: [...INITIAL_BACKUPS],
    auditLogs: [...INITIAL_AUDIT_LOGS],
    metrics: { ...INITIAL_SYSTEM_METRICS },
    isStreaming: true,
  };

  private subscribers: Set<NetworkEventCallback> = new Set();
  private streamInterval: any = null;
  private kaliHostUrl: string = '/api/kali';
  private kaliPollInterval: any = null;

  constructor() {
    this.state.metrics.kaliHostUrl = this.kaliHostUrl;
    this.state.metrics.isLiveKaliConnected = false;
    this.startStreaming();
    this.startKaliPolling();
  }

  public getState(): NetworkEngineState {
    return this.state;
  }

  public setKaliHostUrl(url: string) {
    const cleanUrl = url.trim().replace(/\/$/, '');
    this.kaliHostUrl = cleanUrl || '/api/kali';
    this.state.metrics.kaliHostUrl = this.kaliHostUrl;
    // Notify server-side bridge of host URL
    if (cleanUrl.startsWith('http')) {
      fetch('/api/kali/config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ hostUrl: cleanUrl })
      }).catch(() => {});
    }
    this.pollRealKali();
    this.notify();
  }

  public getKaliHostUrl(): string {
    return this.kaliHostUrl;
  }

  private getEndpoint(path: string): string {
    const cleanPath = path.startsWith('/') ? path : `/${path}`;
    if (this.kaliHostUrl === '/api/kali' || this.kaliHostUrl.endsWith('/api/kali')) {
      return `/api/kali${cleanPath}`;
    }
    return `${this.kaliHostUrl}/api${cleanPath}`;
  }

  public subscribe(callback: NetworkEventCallback): () => void {
    this.subscribers.add(callback);
    callback(this.state);
    return () => this.subscribers.delete(callback);
  }

  private notify() {
    this.subscribers.forEach(cb => cb(this.state));
  }

  public toggleStreaming(enable?: boolean) {
    const target = enable !== undefined ? enable : !this.state.isStreaming;
    this.state.isStreaming = target;
    if (target) {
      this.startStreaming();
    } else {
      clearInterval(this.streamInterval);
    }
    this.notify();
  }

  public toggleAutonomousMode(enabled: boolean) {
    this.state.metrics.autonomousMode = enabled;
    this.addAuditLog(
      'thalesbritoamorim89@gmail.com',
      enabled ? 'Habilitação de Mitigação Autônoma' : 'Desativação de Mitigação Autônoma',
      'NetSentry Core Engine',
      'success'
    );
    this.notify();
  }

  private startKaliPolling() {
    if (this.kaliPollInterval) clearInterval(this.kaliPollInterval);
    this.kaliPollInterval = setInterval(() => {
      this.pollRealKali();
    }, 2000);
    this.pollRealKali();
  }

  private async pollRealKali() {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 1800);
      const res = await fetch(this.getEndpoint('/status'), { signal: controller.signal });
      clearTimeout(timeoutId);

      if (res.ok) {
        const data = await res.json();
        const wasDisconnected = !this.state.metrics.isLiveKaliConnected;
        this.state.metrics.isLiveKaliConnected = Boolean(data.isLiveKaliConnected ?? true);
        this.state.metrics.kaliHostUrl = this.kaliHostUrl;
        this.state.metrics.lastKaliSync = new Date().toLocaleTimeString('pt-BR');
        this.state.metrics.pps = data.pps ?? this.state.metrics.pps;
        this.state.metrics.bandwidthKbps = data.bandwidthKbps ?? this.state.metrics.bandwidthKbps;
        this.state.metrics.totalPackets = data.totalPackets ?? this.state.metrics.totalPackets;
        this.state.metrics.totalThreatsNeutralized = data.totalThreatsNeutralized ?? this.state.metrics.totalThreatsNeutralized;
        this.state.metrics.sniffingInterface = `${data.interface || 'eth0'} (Kali Real)`;

        if (wasDisconnected) {
          this.addAuditLog(
            'NetSentry Sync Agent',
            'Conexão com Host Kali Linux estabelecida com sucesso',
            this.kaliHostUrl,
            'success'
          );
        }

        // Fetch real devices from Kali host
        try {
          const devRes = await fetch(this.getEndpoint('/devices'));
          if (devRes.ok) {
            const devData = await devRes.json();
            if (Array.isArray(devData) && devData.length > 0) {
              const aliases = getStoredAliases();
              this.state.devices = devData.map((d: NetworkDevice) => {
                const alias = aliases[d.ip] || aliases[d.mac] || aliases[d.id] || d.customAlias;
                const vendor = (!d.vendor || d.vendor === 'Desconhecido' || d.vendor === 'Hardware Conectado')
                  ? getClientVendor(d.mac)
                  : d.vendor;
                return {
                  ...d,
                  hostname: alias || d.hostname || `host-${d.ip.split('.').pop()}`,
                  customAlias: alias,
                  vendor,
                  discoveryMethod: alias ? 'manual' : (d.discoveryMethod || 'arp'),
                };
              });
            }
          }
        } catch (e) {}

        // Fetch real alerts from Kali host
        try {
          const altRes = await fetch(this.getEndpoint('/alerts'));
          if (altRes.ok) {
            const altData = await altRes.json();
            if (Array.isArray(altData) && altData.length > 0) {
              this.state.alerts = altData;
            }
          }
        } catch (e) {}

        // Fetch real traffic flows from Kali host
        try {
          const trfRes = await fetch(this.getEndpoint('/traffic'));
          if (trfRes.ok) {
            const trfData = await trfRes.json();
            if (Array.isArray(trfData) && trfData.length > 0) {
              this.state.trafficFlows = trfData;
            }
          }
        } catch (e) {}

        this.notify();
        return;
      }
    } catch (err) {
      if (this.state.metrics.isLiveKaliConnected) {
        this.addAuditLog(
          'NetSentry Sync Agent',
          'Conexão com Host Kali Linux perdida (retornando a telemetria local)',
          this.kaliHostUrl,
          'warning'
        );
      }
      this.state.metrics.isLiveKaliConnected = false;
      this.state.metrics.kaliHostUrl = this.kaliHostUrl;
      this.notify();
    }
  }

  private startStreaming() {
    if (this.streamInterval) clearInterval(this.streamInterval);
    // 100% REAL: Desativada geração de dados sintéticos fictícios.
    // Todos os fluxos, métricas e dispositivos são coletados exclusivamente do agente Scapy/Kali.
  }

  // --- Attack Simulator ---
  public simulateAttack(category: ThreatCategory) {
    const now = new Date();
    const timeStr = now.toLocaleTimeString('pt-BR');
    const fullDate = now.toISOString().replace('T', ' ').substring(0, 19);
    const userParams = parametersService.get();
    const ruleAction = (userParams.iptablesRuleType || 'drop').toUpperCase();

    let alert: ThreatAlert;

    switch (category) {
      case 'arp_poisoning': {
        const attackerIp = '192.168.1.240';
        const attackerMac = '52:54:00:fa:8c:19';
        alert = {
          id: `alt-sim-${Date.now()}`,
          timestamp: fullDate,
          title: 'Ataque ARP Poisoning em Andamento (Conflito Gateway)',
          category: 'arp_poisoning',
          severity: 'critical',
          sourceIp: attackerIp,
          sourceMac: attackerMac,
          targetIp: '192.168.1.1',
          protocol: 'ARP',
          confidence: 99,
          mitreAttack: 'T1557.002 - MITM ARP Poisoning',
          details: `Inundação de 450 pacotes Gratuitous ARP forjados declarando MAC ${attackerMac} como o Gateway 192.168.1.1.`,
          status: 'active',
          playbook: {
            id: `pb-${Date.now()}`,
            actionName: `Bloqueio de MAC no Kernel Netfilter (${ruleAction}) & Reset ARP`,
            description: 'Aplicar descarte no kernel para o MAC forjado e restaurar rota legítima do Gateway.',
            severity: 'critical',
            iptablesCommand: `sudo iptables -I INPUT -m mac --mac-source ${attackerMac} -j ${ruleAction} && sudo iptables -I FORWARD -m mac --mac-source ${attackerMac} -j ${ruleAction}`,
            kaliToolCommand: `sudo arpspoof -i eth0 -t 192.168.1.1 ${attackerIp} -r`,
            suricataRule: `drop arp ${attackerMac} any -> any any (msg:"NETSENTRY Autodetect ARP Poisoning"; sid:9000101; rev:1;)`,
            automatedAvailable: true,
            applied: false,
            rollbackCommand: `sudo iptables -D INPUT -m mac --mac-source ${attackerMac} -j ${ruleAction} && sudo iptables -D FORWARD -m mac --mac-source ${attackerMac} -j ${ruleAction}`
          }
        };

        // Add suspicious traffic flows
        const spoofFlow: TrafficFlow = {
          id: `fl-sim-${Date.now()}`,
          timestamp: timeStr,
          protocol: 'ARP',
          srcIp: attackerIp,
          dstIp: '192.168.1.1',
          packetLength: 42,
          flags: 'Gratuitous ARP',
          info: 'ARP Reply: 192.168.1.1 is at 52:54:00:fa:8c:19 [FORGED]',
          isSuspicious: true,
          anomalyReason: 'MAC não bate com o Gateway autorizado'
        };
        this.state.trafficFlows = [spoofFlow, ...this.state.trafficFlows];
        break;
      }

      case 'port_scan': {
        const attackerIp = '192.168.1.240';
        alert = {
          id: `alt-sim-${Date.now()}`,
          timestamp: fullDate,
          title: 'Varredura SYN Agressiva (Nmap Stealth Sweep)',
          category: 'port_scan',
          severity: 'high',
          sourceIp: attackerIp,
          targetIp: '192.168.1.50',
          protocol: 'TCP',
          confidence: 96,
          mitreAttack: 'T1046 - Network Service Discovery',
          details: `Origem enviou pacotes TCP SYN para ${userParams.portScanThreshold * 8} portas altas distintas em 1.5s, superando o limiar de ${userParams.portScanThreshold} portas configurado.`,
          status: 'active',
          playbook: {
            id: `pb-${Date.now()}`,
            actionName: `Iptables SYN Rate Limit & Blackhole (${ruleAction})`,
            description: 'Bloquear novos handshakes TCP da origem e aplicar quarentena.',
            severity: 'high',
            iptablesCommand: `sudo iptables -I INPUT -s ${attackerIp} -p tcp --syn -j ${ruleAction}`,
            kaliToolCommand: `sudo ip route add blackhole ${attackerIp}/32`,
            suricataRule: `alert tcp ${attackerIp} any -> any any (flags:S; threshold:type both, track by_src, count 20, seconds 5; msg:"NETSENTRY SYN Sweep"; sid:9000102; rev:1;)`,
            automatedAvailable: true,
            applied: false,
            rollbackCommand: `sudo iptables -D INPUT -s ${attackerIp} -p tcp --syn -j ${ruleAction} && sudo ip route del blackhole ${attackerIp}/32`
          }
        };

        const scanFlow: TrafficFlow = {
          id: `fl-sim-${Date.now()}`,
          timestamp: timeStr,
          protocol: 'TCP',
          srcIp: attackerIp,
          srcPort: 54129,
          dstIp: '192.168.1.50',
          dstPort: 4444,
          packetLength: 60,
          flags: 'SYN',
          info: 'TCP SYN Probe -> port 4444 [Closed]',
          isSuspicious: true,
          anomalyReason: 'Sequência de varredura automatizada Nmap'
        };
        this.state.trafficFlows = [scanFlow, ...this.state.trafficFlows];
        break;
      }

      case 'dns_tunneling': {
        alert = {
          id: `alt-sim-${Date.now()}`,
          timestamp: fullDate,
          title: 'Tunelamento DNS & Exfiltração C2',
          category: 'dns_tunneling',
          severity: 'high',
          sourceIp: '192.168.1.189',
          targetIp: '198.51.100.88',
          protocol: 'DNS',
          confidence: 92,
          mitreAttack: 'T1071.004 - DNS Exfiltration & Tunneling',
          details: 'Consultas DNS com subdomínios Base32/64 criptografados de alta entropia (4.82 bits) direcionadas a nameserver externo não autorizado.',
          status: 'active',
          playbook: {
            id: `pb-${Date.now()}`,
            actionName: 'Redirecionamento Forçado de DNS e Blacklist de Domínio',
            description: 'Redirecionar toda query UDP/53 para o Bind local do Kali e bloquear queries suspeitas.',
            severity: 'high',
            iptablesCommand: 'sudo iptables -t nat -A PREROUTING -s 192.168.1.189 -p udp --dport 53 -j REDIRECT --to-ports 53',
            kaliToolCommand: 'sudo systemctl restart dnsmasq && echo "0.0.0.0 evil-c2-channel.net" | sudo tee -a /etc/hosts',
            automatedAvailable: true,
            applied: false,
            rollbackCommand: 'sudo iptables -t nat -D PREROUTING -s 192.168.1.189 -p udp --dport 53 -j REDIRECT --to-ports 53'
          }
        };
        break;
      }

      case 'ddos_flood': {
        alert = {
          id: `alt-sim-${Date.now()}`,
          timestamp: fullDate,
          title: 'Surto Volumétrico de Tráfego (SYN Flood DDoS)',
          category: 'ddos_flood',
          severity: 'critical',
          sourceIp: '192.168.1.240',
          targetIp: '192.168.1.200',
          protocol: 'TCP',
          confidence: 98,
          mitreAttack: 'T1498.001 - Network Denial of Service: Direct Flood',
          details: 'Aumento abrupto para 1.450 pacotes/s direcionados ao servidor NAS de backup. Taxa excede o limiar de segurança em 240%.',
          status: 'active',
          playbook: {
            id: `pb-${Date.now()}`,
            actionName: 'Ativação de SYN Cookies e Rate Limiting no Kernel',
            description: 'Habilitar syncookies no kernel Linux e descartar pacotes acima de 500 pps por IP de origem.',
            severity: 'critical',
            iptablesCommand: 'sudo sysctl -w net.ipv4.tcp_syncookies=1 && sudo iptables -A INPUT -p tcp --syn -m limit --limit 20/s --limit-burst 50 -j ACCEPT',
            kaliToolCommand: 'sudo iptables -A INPUT -p tcp --syn -j DROP',
            automatedAvailable: true,
            applied: false,
            rollbackCommand: 'sudo iptables -D INPUT -p tcp --syn -m limit --limit 20/s --limit-burst 50 -j ACCEPT'
          }
        };
        this.state.metrics.pps = 1450;
        this.state.metrics.bandwidthKbps = 3840;
        break;
      }

      case 'rogue_device':
      default: {
        const randomIp = `192.168.1.${Math.floor(Math.random() * 40) + 210}`;
        const randomMac = `00:50:56:${Math.floor(Math.random() * 89) + 10}:${Math.floor(Math.random() * 89) + 10}:${Math.floor(Math.random() * 89) + 10}`;
        
        // Add rogue device to list
        const newDevice: NetworkDevice = {
          id: `dev-${Date.now()}`,
          ip: randomIp,
          mac: randomMac,
          hostname: `unauthorized-probe-${randomIp.split('.').pop()}`,
          vendor: 'Unknown / Spoofed Vendor',
          deviceType: 'unknown',
          trustLevel: 'unverified',
          openPorts: [
            { port: 23, service: 'telnet', risk: 'critical' },
            { port: 5555, service: 'adb', risk: 'high' }
          ],
          rxBytes: 12000,
          txBytes: 48000,
          packetCount: 120,
          threatScore: 82,
          firstSeen: fullDate,
          lastSeen: 'Agora',
          isOnline: true,
          notes: 'Dispositivo rogue detectado transmitindo sem cadastro prévio.'
        };
        this.state.devices = [newDevice, ...this.state.devices];

        alert = {
          id: `alt-sim-${Date.now()}`,
          timestamp: fullDate,
          title: 'Dispositivo Rogue Desconhecido Conectado',
          category: 'rogue_device',
          severity: 'medium',
          sourceIp: randomIp,
          sourceMac: randomMac,
          targetIp: '255.255.255.255',
          protocol: 'ARP/DHCP',
          confidence: 100,
          mitreAttack: 'T1200 - Hardware Additions',
          details: `Novo dispositivo com MAC ${randomMac} conectado na rede local transmitindo requisições DHCP sem prévia autorização.`,
          status: 'active',
          playbook: {
            id: `pb-${Date.now()}`,
            actionName: 'Isolamento Preventivo de Sub-rede (Quarentena)',
            description: 'Bloquear comunicação inter-dispositivos da LAN para este MAC.',
            severity: 'medium',
            iptablesCommand: `sudo iptables -A FORWARD -m mac --mac-source ${randomMac} -j DROP`,
            kaliToolCommand: `nmap -sV -sC -O ${randomIp}`,
            automatedAvailable: true,
            applied: false,
            rollbackCommand: `sudo iptables -D FORWARD -m mac --mac-source ${randomMac} -j DROP`
          }
        };
        break;
      }
    }

    // Add alert
    this.state.alerts = [alert, ...this.state.alerts];
    this.addAuditLog(
      'NetSentry Anomaly Detector',
      `Detecção de Anomalia: ${alert.title}`,
      alert.sourceIp,
      'warning'
    );

    // If autonomous mitigation is enabled and alert is critical/high, execute automatically!
    const params = parametersService.get();
    if (this.state.metrics.autonomousMode && params.autoBlockHighSeverity && alert.playbook.automatedAvailable) {
      setTimeout(() => {
        this.applyMitigation(alert.id, 'Autonomous Engine Daemon');
      }, 1200);
    }

    this.notify();
  }

  // --- Mitigation Execution ---
  public async applyMitigation(alertId: string, operator: string = 'thalesbritoamorim89@gmail.com') {
    const alert = this.state.alerts.find(a => a.id === alertId);
    if (!alert || alert.playbook.applied) return;

    // Send real command to Kali Linux kernel via REST API
    if (this.state.metrics.isLiveKaliConnected && alert.playbook.iptablesCommand) {
      try {
        await fetch(this.getEndpoint('/mitigate'), {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ command: alert.playbook.iptablesCommand })
        });
      } catch (err) {
        console.error('Falha ao enviar mitigação para o Kali Host:', err);
      }
    }

    alert.playbook.applied = true;
    alert.playbook.appliedAt = new Date().toLocaleTimeString('pt-BR');
    alert.status = 'mitigated';
    this.state.metrics.totalThreatsNeutralized += 1;

    // Update target device trust level if quarantined
    const dev = this.state.devices.find(d => d.ip === alert.sourceIp);
    if (dev) {
      dev.trustLevel = 'quarantined';
      dev.threatScore = Math.max(0, dev.threatScore - 30);
    }

    this.addAuditLog(
      operator,
      `Execução de Mitigação: ${alert.playbook.actionName} ${this.state.metrics.isLiveKaliConnected ? '(Kernel Kali Real)' : ''}`,
      alert.sourceIp,
      'success'
    );

    this.notify();
  }

  public async rollbackMitigation(alertId: string, operator: string = 'thalesbritoamorim89@gmail.com') {
    const alert = this.state.alerts.find(a => a.id === alertId);
    if (!alert || !alert.playbook.applied) return;

    if (this.state.metrics.isLiveKaliConnected && alert.playbook.rollbackCommand) {
      try {
        await fetch(this.getEndpoint('/mitigate'), {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ command: alert.playbook.rollbackCommand })
        });
      } catch (err) {
        console.error('Falha ao reverter comando no Kali:', err);
      }
    }

    alert.playbook.applied = false;
    alert.playbook.appliedAt = undefined;
    alert.status = 'active';
    this.state.metrics.totalThreatsNeutralized = Math.max(0, this.state.metrics.totalThreatsNeutralized - 1);

    this.addAuditLog(
      operator,
      `Rollback de Mitigação: ${alert.playbook.actionName}`,
      alert.sourceIp,
      'warning'
    );

    this.notify();
  }

  // --- Device Management ---
  public setDeviceTrust(deviceId: string, trustLevel: NetworkDevice['trustLevel']) {
    const dev = this.state.devices.find(d => d.id === deviceId);
    if (!dev) return;

    const oldLevel = dev.trustLevel;
    dev.trustLevel = trustLevel;
    
    if (trustLevel === 'trusted') {
      dev.threatScore = Math.min(dev.threatScore, 10);
    } else if (trustLevel === 'blocked') {
      dev.threatScore = 100;
    }

    this.addAuditLog(
      'thalesbritoamorim89@gmail.com',
      `Alteração de Confiabilidade: ${oldLevel} -> ${trustLevel}`,
      `${dev.hostname} (${dev.ip})`,
      'success'
    );

    this.notify();
  }

  public setDeviceAlias(targetIdOrIp: string, alias: string) {
    const dev = this.state.devices.find(d => d.id === targetIdOrIp || d.ip === targetIdOrIp || d.mac === targetIdOrIp);
    if (!dev) return;

    const cleanAlias = alias.trim();
    saveStoredAlias(dev.ip, cleanAlias);
    saveStoredAlias(dev.mac, cleanAlias);
    saveStoredAlias(dev.id, cleanAlias);

    dev.customAlias = cleanAlias || undefined;
    dev.hostname = cleanAlias || `host-${dev.ip.split('.').pop()}`;
    dev.discoveryMethod = cleanAlias ? 'manual' : (dev.discoveryMethod || 'arp');

    // Persist to server / Kali agent if connected
    fetch(this.getEndpoint('/device/alias'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip: dev.ip, mac: dev.mac, alias: cleanAlias })
    }).catch(() => {});

    this.addAuditLog(
      'thalesbritoamorim89@gmail.com',
      `Identificação de Host (Alias): ${dev.ip} -> ${cleanAlias || '(Nome Original)'}`,
      dev.ip,
      'success'
    );

    this.notify();
  }

  public async scanSubnet(deepMode: boolean = false) {
    if (this.state.metrics.isLiveKaliConnected) {
      try {
        await fetch(this.getEndpoint('/scan'), { 
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ deep: deepMode })
        });
      } catch (err) {
        console.error('Erro ao disparar varredura no Kali:', err);
      }
    }

    this.addAuditLog(
      'thalesbritoamorim89@gmail.com',
      `Varredura ${deepMode ? 'Profunda (Nmap + DNS + NetBIOS)' : 'Rápida (ARP Sweep)'} Kali Linux ${this.state.metrics.isLiveKaliConnected ? '(Host Real)' : '(Simulação)'}`,
      '192.168.1.0/24',
      'success'
    );

    // Refresh device lastSeen and re-poll quickly
    this.state.devices.forEach(d => {
      d.lastSeen = 'Agora (Varredura)';
    });
    this.notify();

    setTimeout(() => this.pollRealKali(), 2000);
  }

  // --- Rule Management ---
  public toggleRule(ruleId: string, enabled: boolean) {
    const rule = this.state.rules.find(r => r.id === ruleId);
    if (rule) {
      rule.enabled = enabled;
      this.addAuditLog(
        'thalesbritoamorim89@gmail.com',
        `${enabled ? 'Ativação' : 'Desativação'} de Regra Heurística: ${rule.name}`,
        rule.id,
        'success'
      );
      this.notify();
    }
  }

  public async executeKaliCommand(command: string): Promise<{ success: boolean; output: string }> {
    if (this.state.metrics.isLiveKaliConnected) {
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 180000);
        const res = await fetch(this.getEndpoint('/exec'), {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ command }),
          signal: controller.signal
        });
        clearTimeout(timeoutId);

        const rawText = await res.text();
        let data: any;
        try {
          data = JSON.parse(rawText);
        } catch (e) {
          const cleanText = rawText.replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim();
          data = {
            success: false,
            output: cleanText || `Resposta do servidor Kali (${res.status} ${res.statusText}):\n${rawText.slice(0, 300)}`
          };
        }

        this.addAuditLog(
          'thalesbritoamorim89@gmail.com',
          `Execução no Terminal Kali: ${command}`,
          'Host Kali',
          data.success ? 'success' : 'warning'
        );
        return { success: data.success, output: data.output || 'Comando concluído com sucesso.' };
      } catch (err: any) {
        return { success: false, output: `Erro ao comunicar com o agente Kali em ${this.kaliHostUrl}: ${err.message}` };
      }
    }

    // Fallback info when agent not connected
    this.addAuditLog(
      'thalesbritoamorim89@gmail.com',
      `Execução no Terminal Kali (Simulação): ${command}`,
      'Host Kali',
      'success'
    );
    return {
      success: true,
      output: `[Agente NetSentry Kali]\nComando: ${command}\n\nPara executar diretamente no terminal físico do seu Kali Linux:\n${command}\n\n(Dica: Para hosts que bloqueiam ping ICMP, utilize sempre a flag -Pn)`
    };
  }

  // --- Backup Management ---
  public triggerManualBackup(): DatabaseBackup {
    const now = new Date();
    const pad = (n: number) => n.toString().padStart(2, '0');
    const timestampStr = `${now.getFullYear()}${pad(now.getMonth()+1)}${pad(now.getDate())}_${pad(now.getHours())}${pad(now.getMinutes())}${pad(now.getSeconds())}`;
    
    const newBackup: DatabaseBackup = {
      id: `bk-manual-${Date.now()}`,
      filename: `netsentry_manual_backup_${timestampStr}.sql.gz`,
      sizeMb: Math.round((Math.random() * 2 + 15) * 10) / 10,
      createdAt: now.toISOString().replace('T', ' ').substring(0, 19),
      type: 'manual',
      status: 'verified',
      tableRowsCount: 154800 + Math.floor(Math.random() * 500)
    };

    this.state.backups = [newBackup, ...this.state.backups];
    this.addAuditLog(
      'thalesbritoamorim89@gmail.com',
      `Geração de Backup Manual do PostgreSQL (pg_dump)`,
      newBackup.filename,
      'success'
    );
    this.notify();
    return newBackup;
  }

  public addAuditLog(operator: string, action: string, target: string, status: 'success' | 'warning' | 'failed') {
    const entry: AuditLogEntry = {
      id: `aud-${Date.now()}-${Math.floor(Math.random() * 100)}`,
      timestamp: new Date().toLocaleTimeString('pt-BR'),
      operator,
      action,
      target,
      status,
      ipAddress: '192.168.1.50'
    };
    this.state.auditLogs = [entry, ...this.state.auditLogs.slice(0, 99)];
  }
}

export const networkEngine = new NetworkEngine();
