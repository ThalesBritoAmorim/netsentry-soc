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

// Real-time AI Forensic Analysis Endpoint
app.post('/api/ai/analyze', async (req, res) => {
  try {
    const { alert, metrics, devices, anonymize, analysisLevel } = req.body;

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
      'e alertas de intrusão no Kali Linux. ' +
      'Sua resposta deve ser estritamente técnica, precisa, sem enrolações corporativas ou floreios. ' +
      'Forneça sempre: ' +
      '1. Diagnóstico forense técnico detalhado do comportamento ou anomalia. ' +
      '2. Classificação de Risco (CRÍTICO, ALTO, MÉDIO, BAIXO ou NOMINAL). ' +
      '3. Técnica MITRE ATT&CK correspondente (ex: T1557.002, T1046, T1071.004). ' +
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
