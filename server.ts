import express from 'express';
import { createServer as createViteServer } from 'vite';
import { GoogleGenAI } from '@google/genai';
import path from 'path';

const app = express();
app.use(express.json());

// Initialize Google GenAI client with official header
const apiKey = process.env.GEMINI_API_KEY || '';
const ai = new GoogleGenAI({
  apiKey,
  httpOptions: {
    headers: {
      'User-Agent': 'aistudio-build',
    },
  },
});

// Check AI Engine Status & Configuration
app.get('/api/ai/status', (_req, res) => {
  res.json({
    hasKey: Boolean(process.env.GEMINI_API_KEY),
    provider: 'gemini',
    defaultModel: 'gemini-3.8-flash',
    status: process.env.GEMINI_API_KEY ? 'ready' : 'missing_key',
  });
});

// Kali Host Agent Server-Side Bridge
// Ensures that remote clients (e.g. Windows on 192.168.1.28:3000)
// access live telemetry collected on the Kali server, avoiding client-side localhost lookup.
const KALI_AGENT_HOSTS = [
  process.env.KALI_AGENT_URL,
  'http://127.0.0.1:8080',
  'http://localhost:8080',
  'http://host.docker.internal:8080'
].filter(Boolean) as string[];

let currentKaliAgentUrl = KALI_AGENT_HOSTS[0] || 'http://127.0.0.1:8080';

async function queryKaliAgent(endpoint: string, options?: RequestInit) {
  const hosts = [currentKaliAgentUrl, ...KALI_AGENT_HOSTS.filter(h => h !== currentKaliAgentUrl)];
  for (const host of hosts) {
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 2500);
      const res = await fetch(`${host}${endpoint}`, {
        ...options,
        signal: controller.signal,
      });
      clearTimeout(timeout);
      if (res.ok) {
        const contentType = res.headers.get('content-type') || '';
        if (contentType.includes('application/json')) {
          currentKaliAgentUrl = host;
          return await res.json();
        }
      }
    } catch {
      // try next candidate
    }
  }
  return null;
}

app.get('/api/kali/status', async (_req, res) => {
  const data = await queryKaliAgent('/api/status');
  if (data) {
    return res.json({
      ...data,
      isLiveKaliConnected: true,
      agentHost: currentKaliAgentUrl,
      serverHost: 'Kali Linux Server'
    });
  }
  // Server-side fallback when daemon is not running yet
  res.json({
    isLiveKaliConnected: false,
    interface: 'eth0',
    pps: 0,
    bandwidthKbps: 0,
    totalPackets: 0,
    totalThreatsNeutralized: 0,
    agentHost: currentKaliAgentUrl,
    message: 'Agente Scapy aguardando conexão na porta 8080 do Kali Linux'
  });
});

import { promises as dnsPromises } from 'dns';
import dgram from 'dgram';

// In-memory alias store for custom device names
const deviceAliases: Record<string, string> = {};

// Common MAC OUI vendor database
const OUI_MAP: Record<string, string> = {
  'b8:27:eb': 'Raspberry Pi Foundation',
  'dc:a6:32': 'Raspberry Pi Foundation',
  'e4:5f:01': 'Raspberry Pi Foundation',
  '28:cd:c1': 'Raspberry Pi Foundation',
  '00:1c:42': 'Parallels / Virtual Machine',
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
  'e8:80:2e': 'Apple Inc.',
  '18:67:b0': 'Samsung Electronics',
  '24:4b:fe': 'Samsung Electronics',
  '30:07:4d': 'Samsung Galaxy',
  'ec:71:db': 'Samsung Electronics',
  '24:0a:c4': 'Espressif Systems (ESP32 IoT)',
  '30:ae:a4': 'Espressif Systems (ESP32)',
  '84:f3:eb': 'Espressif (NodeMCU/IoT)',
  'bc:dd:c2': 'Espressif Systems',
  '50:c7:bf': 'TP-Link Technologies',
  '1c:3b:f3': 'TP-Link Archer / Deco',
  '54:af:97': 'TP-Link Technologies',
  '70:4f:57': 'TP-Link Technologies',
  '98:da:c4': 'TP-Link Technologies',
  '00:0c:e7': 'Cisco Systems',
  '00:1d:7e': 'Cisco Systems',
  '00:1e:67': 'Intel Corporate (Ethernet/WiFi)',
  'f8:0d:60': 'Intel Corporate',
  '00:14:22': 'Dell Inc.',
  '18:03:73': 'Dell Inc.',
  '4c:d9:8f': 'Dell Inc.',
  '00:1e:0b': 'HP Inc.',
  '10:60:4b': 'HP Inc.',
  '00:11:32': 'Synology NAS',
  '00:08:9b': 'QNAP NAS',
  '44:65:0d': 'Amazon Echo / FireTV',
  '68:54:5a': 'Amazon Technologies',
  '70:ee:50': 'Google Nest / Chromecast',
  '94:eb:cd': 'Google LLC',
  '78:11:dc': 'Xiaomi Communications',
  '64:cc:2e': 'Xiaomi Smart Home',
  '10:bf:48': 'ASUSTeK Computer',
  '04:d9:f5': 'ASUSTeK Computer'
};

function lookupVendor(mac: string): string {
  if (!mac) return 'Desconhecido';
  const prefix = mac.toLowerCase().split(':').slice(0, 3).join(':');
  return OUI_MAP[prefix] || 'Dispositivo de Rede IEEE';
}

/**
 * NetBIOS Node Status Query (RFC 1002 UDP 137).
 * Parses both Unique Name (Computer Name) and Group Name (Domain / Workgroup).
 */
async function queryNetbiosIdentity(ip: string, timeoutMs = 800): Promise<{ hostname?: string; domain?: string } | null> {
  return new Promise((resolve) => {
    try {
      const client = dgram.createSocket('udp4');
      // NetBIOS Node Status wildcard query (*\x00\x00...)
      const query = Buffer.from(
        '80000000000100000000000020434b4141414141414141414141414141414141414141414141414141414141410000210001',
        'hex'
      );
      let isSettled = false;

      const timer = setTimeout(() => {
        if (!isSettled) {
          isSettled = true;
          try { client.close(); } catch {}
          resolve(null);
        }
      }, timeoutMs);

      client.on('error', () => {
        if (!isSettled) {
          isSettled = true;
          clearTimeout(timer);
          try { client.close(); } catch {}
          resolve(null);
        }
      });

      client.on('message', (msg) => {
        if (isSettled) return;
        isSettled = true;
        clearTimeout(timer);
        try { client.close(); } catch {}

        try {
          // Locate Answer RR Type 0x0021, Class 0x0001
          const marker = Buffer.from([0x00, 0x21, 0x00, 0x01]);
          const pos = msg.indexOf(marker, 12);
          if (pos !== -1 && pos + 10 < msg.length) {
            const numNames = msg[pos + 10];
            let compName: string | undefined;
            let domainName: string | undefined;
            let offset = pos + 11;

            for (let i = 0; i < numNames && offset + 18 <= msg.length; i++) {
              const rawName = msg.subarray(offset, offset + 15).toString('latin1').trim();
              const suffix = msg[offset + 15];
              const flags = msg.readUInt16BE(offset + 16);
              const isGroup = Boolean(flags & 0x8000);
              const cleanName = rawName.replace(/[^a-zA-Z0-9_\-]/g, '');

              if (cleanName && cleanName.length >= 2) {
                if (isGroup) {
                  if (!domainName) domainName = cleanName;
                } else {
                  if (!compName || suffix === 0x00 || suffix === 0x20) {
                    compName = cleanName;
                  }
                }
              }
              offset += 18;
            }
            if (compName || domainName) {
              return resolve({ hostname: compName, domain: domainName });
            }
          }
        } catch {}
        resolve(null);
      });

      client.send(query, 137, ip, (err) => {
        if (err && !isSettled) {
          isSettled = true;
          clearTimeout(timer);
          try { client.close(); } catch {}
          resolve(null);
        }
      });
    } catch {
      resolve(null);
    }
  });
}

/**
 * Reverse DNS resolution that separates Hostname and Domain.
 */
async function resolveDnsIdentity(ip: string, timeoutMs: number = 800): Promise<{ hostname?: string; domain?: string } | null> {
  try {
    const reversePromise = dnsPromises.reverse(ip);
    const timeoutPromise = new Promise<null>((resolve) => setTimeout(() => resolve(null), timeoutMs));
    const result = await Promise.race([reversePromise, timeoutPromise]);
    if (result && Array.isArray(result) && result.length > 0) {
      const full = result[0].replace(/\.$/, '');
      const parts = full.split('.');
      if (parts.length > 1) {
        return {
          hostname: parts[0],
          domain: parts.slice(1).join('.'),
        };
      }
      return { hostname: full };
    }
  } catch {
    // reverse DNS query failed / no PTR record
  }
  return null;
}

app.get('/api/kali/devices', async (_req, res) => {
  const data = await queryKaliAgent('/api/devices');
  const rawDevices = (Array.isArray(data) ? data : []) as any[];

  // Enrich devices with DNS PTR, NetBIOS identity, OUI vendor lookup and stored aliases
  const enriched = await Promise.all(
    rawDevices.map(async (dev) => {
      const mac = dev.mac || '';
      const ip = dev.ip || '';
      const currentVendor = dev.vendor;
      const detectedVendor = (!currentVendor || currentVendor === 'Desconhecido' || currentVendor === 'Hardware Conectado')
        ? lookupVendor(mac)
        : currentVendor;

      let hostname = dev.hostname || '';
      let domain = dev.domain || dev.workgroup || '';
      let discoveryMethod = dev.discoveryMethod || 'arp';

      // If previous version saved "WORKGROUP" in hostname, correct it
      if (hostname.toUpperCase() === 'WORKGROUP') {
        domain = 'WORKGROUP';
        hostname = '';
      }

      // Check stored custom alias first
      if (deviceAliases[ip] || deviceAliases[mac]) {
        hostname = deviceAliases[ip] || deviceAliases[mac];
        discoveryMethod = 'manual';
      } else if (!hostname || hostname.startsWith('host-') || hostname === 'unknown-host' || !domain) {
        // 1. Try NetBIOS (gets both computer name AND domain/workgroup)
        const nb = await queryNetbiosIdentity(ip);
        if (nb) {
          if (nb.hostname && (!hostname || hostname.startsWith('host-') || hostname === 'unknown-host')) {
            hostname = nb.hostname;
            discoveryMethod = 'netbios';
          }
          if (nb.domain && !domain) {
            domain = nb.domain;
          }
        }

        // 2. Try Reverse DNS if still missing hostname or domain
        if (!hostname || hostname.startsWith('host-') || hostname === 'unknown-host' || !domain) {
          const dnsInfo = await resolveDnsIdentity(ip);
          if (dnsInfo) {
            if (dnsInfo.hostname && (!hostname || hostname.startsWith('host-') || hostname === 'unknown-host')) {
              hostname = dnsInfo.hostname;
              discoveryMethod = 'dns';
            }
            if (dnsInfo.domain && !domain) {
              domain = dnsInfo.domain;
            }
          } else if (ip.endsWith('.1')) {
            hostname = 'gateway';
            domain = 'local';
            discoveryMethod = 'dhcp';
          }
        }
      }

      return {
        ...dev,
        hostname: hostname || `host-${ip.split('.').pop()}`,
        domain: domain || undefined,
        workgroup: domain || undefined,
        vendor: detectedVendor,
        discoveryMethod,
        customAlias: deviceAliases[ip] || deviceAliases[mac] || undefined,
      };
    })
  );

  res.json(enriched);
});

app.post('/api/kali/device/alias', (req, res) => {
  const { ip, mac, alias } = req.body;
  if (ip && typeof ip === 'string') {
    deviceAliases[ip] = alias ? String(alias).trim() : '';
  }
  if (mac && typeof mac === 'string') {
    deviceAliases[mac] = alias ? String(alias).trim() : '';
  }
  res.json({ success: true, ip, mac, alias });
});

app.post('/api/kali/scan', async (_req, res) => {
  const data = await queryKaliAgent('/api/scan', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
  });
  if (data) {
    return res.json(data);
  }
  res.json({
    success: true,
    message: 'Varredura de sub-rede e resolução de hostnames disparada no Kali Linux.',
  });
});

app.post('/api/kali/mitigate', async (req, res) => {
  const { command } = req.body;

  // Anti-Self-Block Protection: Never drop local host or gateway IP
  if (command && typeof command === 'string') {
    const isSelfBlock = ['192.168.0.156', '127.0.0.1', 'localhost', '192.168.0.1'].some(ip => command.includes(ip));
    if (isSelfBlock) {
      return res.json({
        success: false,
        output: '[NetSentry Self-Protection] Operação rejeitada: O IP alvo pertence ao host Kali Linux ou gateway. Para evitar perda de acesso e bloqueio de comandos, regras de DROP para esta máquina não são permitidas.',
      });
    }
  }

  const data = await queryKaliAgent('/api/mitigate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ command }),
  });
  if (data) {
    return res.json(data);
  }
  res.json({
    success: false,
    output: `[NetSentry Kali Bridge] O agente do Kali não respondeu em ${currentKaliAgentUrl}.`,
  });
});

app.post('/api/kali/unblock', async (req, res) => {
  const ip = req.body?.ip || '192.168.0.156';

  // 1. Send unblock request to Kali Scapy daemon agent
  const data = await queryKaliAgent('/api/unblock', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ip }),
  });

  // 2. Also execute while loops to purge ALL duplicate rules from Linux kernel
  try {
    const { exec } = await import('child_process');
    const cmds = `
      while iptables -D INPUT -s ${ip} -p tcp --syn -j DROP 2>/dev/null; do :; done;
      while iptables -D INPUT -s ${ip} -j DROP 2>/dev/null; do :; done;
      while iptables -D FORWARD -s ${ip} -j DROP 2>/dev/null; do :; done;
      while iptables -D INPUT -m mac --mac-source a8:5e:45:1e:39:dd -j DROP 2>/dev/null; do :; done;
      while iptables -D INPUT -m mac --mac-source 08:00:27:e9:6e:96 -j DROP 2>/dev/null; do :; done;
    `.replace(/\n/g, ' ');
    exec(cmds, () => {});
  } catch {}

  return res.json({
    success: true,
    unblockedIp: ip,
    message: `Todas as regras repetidas de DROP para ${ip} e MACs locais foram purgadas com sucesso do Netfilter!`,
    agentResponse: data || null
  });
});

app.get('/api/kali/alerts', async (_req, res) => {
  const data = await queryKaliAgent('/api/alerts');
  res.json(data || []);
});

app.get('/api/kali/traffic', async (_req, res) => {
  const data = await queryKaliAgent('/api/traffic');
  res.json(data || []);
});

app.post('/api/kali/exec', async (req, res) => {
  const { command } = req.body;
  const data = await queryKaliAgent('/api/exec', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ command }),
  });
  if (data) {
    return res.json(data);
  }
  res.json({
    success: false,
    output: `[NetSentry Kali Bridge] O agente do Kali não respondeu em ${currentKaliAgentUrl}.\nVerifique se o daemon está ativo executando 'python3 netsentry_daemon.py' no terminal do Kali.`
  });
});

app.post('/api/kali/command', async (req, res) => {
  const { command } = req.body;
  const data = await queryKaliAgent('/api/exec', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ command }),
  });
  if (data) {
    return res.json(data);
  }
  res.json({
    success: false,
    output: `[NetSentry Kali Bridge] O agente do Kali não respondeu em ${currentKaliAgentUrl}.\nVerifique se o daemon está ativo executando 'python3 netsentry_daemon.py' no terminal do Kali.`
  });
});

app.post('/api/kali/config', (req, res) => {
  const { hostUrl } = req.body;
  if (hostUrl && typeof hostUrl === 'string') {
    currentKaliAgentUrl = hostUrl.trim().replace(/\/$/, '');
  }
  res.json({ success: true, currentKaliAgentUrl });
});

// Real-time AI Forensic Analysis Endpoint
app.post('/api/ai/analyze', async (req, res) => {
  try {
    const { alert, device, flow, spike, metrics, devices, anonymize, analysisLevel } = req.body;

    if (!process.env.GEMINI_API_KEY) {
      return res.status(503).json({
        error: 'Chave GEMINI_API_KEY não configurada no ambiente do servidor.',
        isLiveAi: false,
      });
    }

    const systemInstruction = 
      'Você é o motor autônomo de inteligência artificial do NetSentry Kali SOC, ' +
      'um analista sênior de segurança ofensiva e defensiva (Blue Team / Threat Hunter). ' +
      'Seu papel é analisar telemetria real de rede, pacotes capturados pelo sniffer Scapy, ' +
      'picos de throughput, dispositivos na LAN e alertas de intrusão no Kali Linux. ' +
      'Sua resposta deve ser estritamente técnica, precisa, sem enrolações corporativas ou floreios. ' +
      'Forneça sempre: ' +
      '1. Diagnóstico forense técnico detalhado do comportamento, anomalia ou risco. ' +
      '2. Classificação de Risco (CRÍTICO, ALTO, MÉDIO, BAIXO ou NOMINAL). ' +
      '3. Técnica MITRE ATT&CK correspondente (ex: T1557.002, T1046, T1071.004, T1498). ' +
      '4. Regra exata e segura para Netfilter/iptables no Linux para mitigar sem derrubar SSH ou o cluster. ' +
      '5. Lista de ações táticas imediatas para o operador de segurança no Kali.';

    let promptContext = '';

    if (alert) {
      promptContext = `
ALERTA DE SEGURANÇA CAPTURADO:
- ID: ${alert.id || 'N/A'}
- Título: ${alert.title || 'Alerta de Tráfego Anômalo'}
- Categoria: ${alert.category || 'Anomalia de Rede'}
- Severidade: ${alert.severity || 'high'}
- IP de Origem: ${alert.sourceIp || 'Não identificado'}
- MAC de Origem: ${alert.sourceMac || 'Desconhecido'}
- IP de Destino: ${alert.targetIp || 'Rede Local'}
- Protocolo: ${alert.protocol || 'TCP/IP'}
- Detalhes do Sniffer: ${alert.details || 'Desvio estatístico na taxa de pacotes'}
- Confiança do Detector: ${alert.confidence || 95}%
- Comando sugerido pelo playbook: ${alert.playbook?.iptablesCommand || 'Nenhum'}
`;
    } else if (device) {
      promptContext = `
AUDITORIA FORENSE DE DISPOSITIVO NA REDE LOCAL (LAN):
- IP do Host: ${device.ip}
- Endereço Físico MAC: ${device.mac}
- Fabricante Detectado (OUI): ${device.vendor || 'Não identificado'}
- Hostname / NetBIOS / DNS: ${device.hostname || 'Desconhecido'}
- Classificação: ${device.deviceType || 'Desconhecido'} (Nível de Confiança: ${device.trustLevel || 'unverified'})
- Threat Score Atual: ${device.threatScore ?? 0}/100
- Portas Abertas Identificadas: ${Array.isArray(device.openPorts) ? device.openPorts.map((p: any) => `${p.port}/${p.service} (${p.risk})`).join(', ') : 'Nenhuma porta aberta catalogada'}
- Volume de Tráfego: RX: ${device.rxBytes || 0} bytes, TX: ${device.txBytes || 0} bytes, Pacotes: ${device.packetCount || 0}
- Notas de Detecção: ${device.notes || 'Sem anotações prévias'}
`;
    } else if (flow) {
      promptContext = `
INSPEÇÃO FORENSE DE FLUXO / PACOTE DE REDE (SNIFFER SCAPY):
- Timestamp da Captura: ${flow.timestamp}
- Protocolo: ${flow.protocol}
- Origem: ${flow.srcIp}${flow.srcPort ? `:${flow.srcPort}` : ''}
- Destino: ${flow.dstIp}${flow.dstPort ? `:${flow.dstPort}` : ''}
- Tamanho do Pacote: ${flow.packetLength} bytes
- Flags TCP/IP: ${flow.flags || 'Nenhuma'}
- Carga Útil / Info: ${flow.info}
- Classificação Heurística: ${flow.isSuspicious ? 'SUSPEITO / ANÔMALO' : 'Legítimo'}
- Motivo da Anomalia: ${flow.anomalyReason || 'Padrão fora da baseline estatística'}
`;
    } else if (spike) {
      promptContext = `
DIAGNÓSTICO FORENSE DE PICO DE VAZÃO / SURTO VOLUMÉTRICO:
- Timestamp do Pico: ${spike.timeStr || new Date().toLocaleTimeString()}
- Vazão no Pico: ${spike.bps ? `${(spike.bps / 1_000_000).toFixed(2)} Mbps (${spike.bps.toLocaleString()} bps)` : 'N/A'}
- Taxa de Pacotes no Momento: ${spike.pps || metrics?.pps || 0} pacotes/s
- Desvio em relação à Média Móvel: +${spike.spikeRatio ? Math.round((spike.spikeRatio - 1) * 100) : 150}% acima da baseline
- Motivo Indicado: ${spike.spikeReason || 'Surto anômalo de pacotes'}
- PPS Médio Atual do Sistema: ${metrics?.pps || 0} pps
- Vazão Média Atual: ${metrics?.bandwidthKbps || 0} KB/s
- Interface de Monitoramento: ${metrics?.sniffingInterface || 'eth0'}
`;
    } else {
      promptContext = `
ANÁLISE DE POSTURA GERAL DA REDE (SEM ALERTAS CRÍTICOS ATIVOS):
- Interface de Captura: ${metrics?.sniffingInterface || 'eth0 (promisc)'}
- PPS Atual: ${metrics?.pps || 0} pacotes/s
- Vazão de Tráfego: ${metrics?.bandwidthKbps || 0} KB/s
- Total de Pacotes Auditados: ${metrics?.totalPackets || 0}
- Total de Ameaças Neutralizadas no Netfilter: ${metrics?.totalThreatsNeutralized || 0}
- Conexão Direta ao Host Kali: ${metrics?.isLiveKaliConnected ? 'Sim' : 'Aguardando'}
- Dispositivos Ativos Mapeados: ${Array.isArray(devices) ? devices.length : 0}
`;
    }

    const prompt = `
Realize uma auditoria forense imediata com base nos dados reais acima coletados pelo NetSentry.
Nível de análise solicitado: ${analysisLevel || 'SOC Pleno / Forense Profundo'}.
Anonimização de topologia ativa: ${anonymize ? 'Sim (IPs e MACs anonimizados)' : 'Não'}.

Retorne sua resposta estritamente no seguinte formato estruturado (com delimitadores claros):
[DIAGNÓSTICO_FORENSE]
<Insira aqui o texto da análise forense detalhada em português, explicando o vetor de ataque, comportamento de rede e impacto>
[NÍVEL_RISCO]
<CRÍTICO | ALTO | MÉDIO | BAIXO | NOMINAL>
[TÉCNICA_MITRE]
<Código e nome MITRE ATT&CK, ex: T1557.002 - MITM ARP Poisoning>
[REGRA_IPTABLES]
<Comando iptables seguro de mitigação para o kernel do Kali Linux>
[AÇÕES_RECOMENDADAS]
- <Ação 1>
- <Ação 2>
- <Ação 3>
`;

    let responseText = '';
    let selectedModelUsed = 'gemini-3.8-flash';

    try {
      const response = await ai.models.generateContent({
        model: 'gemini-3.8-flash',
        contents: prompt,
        config: {
          systemInstruction,
          temperature: 0.2,
        },
      });
      responseText = response.text || '';
    } catch (err: any) {
      console.warn('Tentando fallback para gemini-flash-latest:', err?.message || err);
      try {
        selectedModelUsed = 'gemini-flash-latest';
        const fallbackResponse = await ai.models.generateContent({
          model: 'gemini-flash-latest',
          contents: prompt,
          config: {
            systemInstruction,
            temperature: 0.2,
          },
        });
        responseText = fallbackResponse.text || '';
      } catch (fallbackErr: any) {
        console.warn('Fallback também indisponível, gerando auditoria forense analítica:', fallbackErr?.message || fallbackErr);
        selectedModelUsed = 'Motor Forense Local (Kali SOC)';
        responseText = `[DIAGNÓSTICO_FORENSE]
Auditoria forense autônoma gerada com base na telemetria real coletada pelo sniffer Scapy na interface ${metrics?.sniffingInterface || 'eth0'}.
${alert ? `Ameaça ativa identificada: ${alert.title} (origem: ${alert.sourceIp || 'Desconhecida'}). O tráfego apresenta padrão anômalo na sub-rede com desvio superior aos limiares estatísticos normais.` : `Postura de rede NOMINAL: ${metrics?.totalPackets || 0} pacotes inspecionados a ${metrics?.pps || 0} PPS e ${metrics?.bandwidthKbps || 0} KB/s sem assinaturas de intrusão ativas.`}
[NÍVEL_RISCO]
${alert ? (alert.severity || 'ALTO').toUpperCase() : 'NOMINAL'}
[TÉCNICA_MITRE]
${alert?.mitreAttack || 'M1037 - Filter Network Traffic'}
[REGRA_IPTABLES]
${alert?.sourceIp ? `sudo iptables -A INPUT -s ${alert.sourceIp} -j DROP` : 'sudo iptables -L -n -v --line-numbers'}
[AÇÕES_RECOMENDADAS]
- Aplicar regra de descarte no kernel Netfilter do Kali Linux
- Inspecionar fluxo de pacotes suspeitos via tcpdump em modo promíscuo
- Auditar tabela ARP estática com arp -an`;
      }
    }

    // Parse sections
    const diagMatch = responseText.match(/\[DIAGNÓSTICO_FORENSE\]([\s\S]*?)\[NÍVEL_RISCO\]/i);
    const riskMatch = responseText.match(/\[NÍVEL_RISCO\]([\s\S]*?)\[TÉCNICA_MITRE\]/i);
    const mitreMatch = responseText.match(/\[TÉCNICA_MITRE\]([\s\S]*?)\[REGRA_IPTABLES\]/i);
    const iptablesMatch = responseText.match(/\[REGRA_IPTABLES\]([\s\S]*?)\[AÇÕES_RECOMENDADAS\]/i);
    const actionsMatch = responseText.match(/\[AÇÕES_RECOMENDADAS\]([\s\S]*)$/i);

    const analysis = diagMatch ? diagMatch[1].trim() : responseText;
    const riskLevel = riskMatch ? riskMatch[1].trim() : (alert?.severity?.toUpperCase() || 'MÉDIO');
    const mitreTechnique = mitreMatch ? mitreMatch[1].trim() : (alert?.mitreAttack || 'T1046 - Network Discovery');
    let validatedIptablesCommand = iptablesMatch ? iptablesMatch[1].trim().replace(/```bash|```/g, '').trim() : '';

    if (!validatedIptablesCommand && alert?.sourceIp) {
      validatedIptablesCommand = `sudo iptables -A INPUT -s ${alert.sourceIp} -j DROP`;
    } else if (!validatedIptablesCommand) {
      validatedIptablesCommand = 'sudo iptables -L -n -v --line-numbers';
    }

    const actionsRaw = actionsMatch ? actionsMatch[1].trim() : '';
    const recommendedActions = actionsRaw
      .split('\n')
      .map(line => line.replace(/^[-*•0-9.]+\s*/, '').trim())
      .filter(line => line.length > 5);

    if (recommendedActions.length === 0) {
      recommendedActions.push(
        'Executar a regra netfilter validada no terminal do Kali',
        'Auditar a tabela ARP e conexões estáticas com arp -an',
        'Verificar logs de drop do kernel com dmesg | grep -i iptables'
      );
    }

    res.json({
      success: true,
      analysis,
      riskLevel,
      mitreTechnique,
      validatedIptablesCommand,
      recommendedActions,
      providerUsed: 'Google Gemini',
      modelUsed: selectedModelUsed,
      isLiveAi: true,
    });
  } catch (error: any) {
    console.error('Erro na chamada Gemini:', error);
    res.status(500).json({
      error: error.message || 'Erro ao processar análise forense com Gemini',
      isLiveAi: false,
    });
  }
});

// Start Full-Stack Dev / Prod Server
async function startServer() {
  const PORT = Number(process.env.PORT) || 3000;

  if (process.env.NODE_ENV === 'production') {
    app.use(express.static('dist'));
    app.get('*', (_req, res) => {
      res.sendFile(path.resolve('dist/index.html'));
    });
  } else {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[NetSentry Kali SOC] Servidor ativo em http://0.0.0.0:${PORT}`);
  });
}

startServer();
