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
  private kaliHostUrl: string = 'http://localhost:8080';
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
    this.kaliHostUrl = url.trim().replace(/\/$/, '');
    this.state.metrics.kaliHostUrl = this.kaliHostUrl;
    this.pollRealKali();
    this.notify();
  }

  public getKaliHostUrl(): string {
    return this.kaliHostUrl;
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
      const res = await fetch(`${this.kaliHostUrl}/api/status`, { signal: controller.signal });
      clearTimeout(timeoutId);

      if (res.ok) {
        const data = await res.json();
        const wasDisconnected = !this.state.metrics.isLiveKaliConnected;
        this.state.metrics.isLiveKaliConnected = true;
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
          const devRes = await fetch(`${this.kaliHostUrl}/api/devices`);
          if (devRes.ok) {
            const devData = await devRes.json();
            if (Array.isArray(devData) && devData.length > 0) {
              this.state.devices = devData;
            }
          }
        } catch (e) {}

        // Fetch real alerts from Kali host
        try {
          const altRes = await fetch(`${this.kaliHostUrl}/api/alerts`);
          if (altRes.ok) {
            const altData = await altRes.json();
            if (Array.isArray(altData) && altData.length > 0) {
              this.state.alerts = altData;
            }
          }
        } catch (e) {}

        // Fetch real traffic flows from Kali host
        try {
          const trfRes = await fetch(`${this.kaliHostUrl}/api/traffic`);
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
    this.streamInterval = setInterval(() => {
      if (!this.state.isStreaming || this.state.metrics.isLiveKaliConnected) return;
      this.generateLiveTick();
    }, 2500);
  }

  private generateLiveTick() {
    const now = new Date();
    const timeStr = now.toLocaleTimeString('pt-BR');

    // Generate normal traffic variation
    const protocols: Array<'TCP' | 'UDP' | 'TLS' | 'DNS' | 'HTTP' | 'ICMP'> = ['TCP', 'TLS', 'UDP', 'DNS', 'HTTP', 'ICMP'];
    const proto = protocols[Math.floor(Math.random() * protocols.length)];
    const devices = this.state.devices.filter(d => d.trustLevel !== 'blocked');
    const src = devices[Math.floor(Math.random() * devices.length)] || devices[0];
    const dst = devices[Math.floor(Math.random() * devices.length)] || devices[1];

    const length = Math.floor(Math.random() * 900) + 64;
    const newFlow: TrafficFlow = {
      id: `fl-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
      timestamp: timeStr,
      protocol: proto,
      srcIp: src.ip,
      srcPort: Math.floor(Math.random() * 40000) + 1024,
      dstIp: dst.ip,
      dstPort: proto === 'DNS' ? 53 : proto === 'HTTP' ? 80 : proto === 'TLS' ? 443 : 22,
      packetLength: length,
      flags: proto === 'TCP' ? 'ACK, PSH' : undefined,
      info: `${proto} normal payload transfer (${length} bytes)`,
      isSuspicious: false
    };

    // Update state
    this.state.trafficFlows = [newFlow, ...this.state.trafficFlows.slice(0, 49)];
    this.state.metrics.totalPackets += Math.floor(Math.random() * 18) + 4;
    this.state.metrics.pps = Math.floor(Math.random() * 50) + 110;
    this.state.metrics.bandwidthKbps = Math.round((Math.random() * 300 + 700) * 10) / 10;

    // Increment byte counters on devices
    src.txBytes += length;
    dst.rxBytes += length;
    src.lastSeen = 'Agora';

    this.notify();
  }

  // --- Attack Simulator ---
  public simulateAttack(category: ThreatCategory) {
    const now = new Date();
    const timeStr = now.toLocaleTimeString('pt-BR');
    const fullDate = now.toISOString().replace('T', ' ').substring(0, 19);

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
            actionName: 'Bloqueio de MAC no Kernel Netfilter & Reset ARP',
            description: 'Dropar tráfego do MAC forjado na tabela de filtro e restaurar rota ARP legítima do Gateway.',
            severity: 'critical',
            iptablesCommand: `sudo iptables -I INPUT -m mac --mac-source ${attackerMac} -j DROP && sudo iptables -I FORWARD -m mac --mac-source ${attackerMac} -j DROP`,
            kaliToolCommand: `sudo arpspoof -i eth0 -t 192.168.1.1 ${attackerIp} -r`,
            suricataRule: `drop arp ${attackerMac} any -> any any (msg:"NETSENTRY Autodetect ARP Poisoning"; sid:9000101; rev:1;)`,
            automatedAvailable: true,
            applied: false,
            rollbackCommand: `sudo iptables -D INPUT -m mac --mac-source ${attackerMac} -j DROP && sudo iptables -D FORWARD -m mac --mac-source ${attackerMac} -j DROP`
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
          details: `Origem enviou pacotes TCP SYN para 180 portas altas distintas do nó Kali Linux em 1.8 segundos sem finalizar handshake.`,
          status: 'active',
          playbook: {
            id: `pb-${Date.now()}`,
            actionName: 'Iptables SYN Rate Limit & Blackhole Temporário',
            description: 'Bloquear novos handshakes TCP da origem e aplicar quarentena de 1 hora.',
            severity: 'high',
            iptablesCommand: `sudo iptables -I INPUT -s ${attackerIp} -p tcp --syn -j DROP`,
            kaliToolCommand: `sudo ip route add blackhole ${attackerIp}/32`,
            suricataRule: `alert tcp ${attackerIp} any -> any any (flags:S; threshold:type both, track by_src, count 20, seconds 5; msg:"NETSENTRY SYN Sweep"; sid:9000102; rev:1;)`,
            automatedAvailable: true,
            applied: false,
            rollbackCommand: `sudo iptables -D INPUT -s ${attackerIp} -p tcp --syn -j DROP && sudo ip route del blackhole ${attackerIp}/32`
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
    if (this.state.metrics.autonomousMode && alert.playbook.automatedAvailable) {
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
        await fetch(`${this.kaliHostUrl}/api/mitigate`, {
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
        await fetch(`${this.kaliHostUrl}/api/mitigate`, {
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

  public async scanSubnet() {
    if (this.state.metrics.isLiveKaliConnected) {
      try {
        await fetch(`${this.kaliHostUrl}/api/scan`, { method: 'POST' });
      } catch (err) {
        console.error('Erro ao disparar varredura no Kali:', err);
      }
    }

    this.addAuditLog(
      'thalesbritoamorim89@gmail.com',
      `Varredura ARP Sub-rede Kali Linux ${this.state.metrics.isLiveKaliConnected ? '(Host Real)' : '(Simulação)'}`,
      '192.168.1.0/24',
      'success'
    );
    // Refresh device lastSeen
    this.state.devices.forEach(d => {
      d.lastSeen = 'Agora (Varredura)';
    });
    this.notify();
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
        const res = await fetch(`${this.kaliHostUrl}/api/exec`, {
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
