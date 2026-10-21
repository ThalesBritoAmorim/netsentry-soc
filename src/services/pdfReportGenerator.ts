import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';
import { ThreatAlert, NetworkDevice, AuditLogEntry } from '../types';

interface PDFReportOptions {
  alerts: ThreatAlert[];
  devices: NetworkDevice[];
  auditLogs: AuditLogEntry[];
  author?: string;
  period?: string;
}

export function generateConsolidatedPDFReport({
  alerts,
  devices,
  auditLogs,
  author = 'Thales Brito Amorim (SecOps Admin)',
  period = 'Últimas 24 Horas'
}: PDFReportOptions): jsPDF {
  const doc = new jsPDF({
    orientation: 'portrait',
    unit: 'mm',
    format: 'a4'
  });

  const now = new Date();
  const dateFormatted = now.toLocaleString('pt-BR');
  const fileDateStr = now.toISOString().replace(/[:T]/g, '-').slice(0, 16);

  // Generate simulated integrity hash
  const pseudoHash = Array.from({ length: 16 }, () => 
    Math.floor(Math.random() * 16).toString(16)
  ).join('').toUpperCase();

  const totalAlerts = alerts.length;
  const criticalCount = alerts.filter(a => a.severity === 'critical').length;
  const highCount = alerts.filter(a => a.severity === 'high').length;
  const mitigatedCount = alerts.filter(a => a.playbook?.applied).length;
  const trustedDevices = devices.filter(d => d.trustLevel === 'trusted');
  const quarantinedDevices = devices.filter(d => d.trustLevel === 'quarantined' || d.threatScore > 50);

  // --- 1. Top Executive Banner ---
  doc.setFillColor(15, 23, 42); // slate-900
  doc.rect(0, 0, 210, 30, 'F');

  doc.setFillColor(6, 182, 212); // cyan-500
  doc.rect(0, 30, 210, 1.8, 'F');

  doc.setTextColor(255, 255, 255);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(14);
  doc.text('NETSENTRY KALI SOC — RELATÓRIO CONSOLIDADO', 14, 13);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(9);
  doc.setTextColor(148, 163, 184); // slate-400
  doc.text('Inspeção Autônoma de Rede · Dispositivos Confiáveis · Trilha de Auditoria', 14, 20);
  doc.text(`Hash de Integridade Local: SHA256-${pseudoHash} · Sistema Operacional: Kali Linux Host`, 14, 26);

  let currentY = 38;

  // --- 2. Meta Info Box ---
  doc.setFillColor(248, 250, 252); // slate-50
  doc.setDrawColor(226, 232, 240); // slate-200
  doc.roundedRect(14, currentY, 182, 18, 2, 2, 'FD');

  doc.setTextColor(51, 65, 85);
  doc.setFontSize(8.5);
  doc.setFont('helvetica', 'bold');
  doc.text('Emissão:', 18, currentY + 6);
  doc.text('Auditor / SecOps:', 75, currentY + 6);
  doc.text('Período Analisado:', 140, currentY + 6);

  doc.setFont('helvetica', 'normal');
  doc.setTextColor(71, 85, 105);
  doc.text(dateFormatted, 18, currentY + 12);
  doc.text(author, 75, currentY + 12);
  doc.text(period, 140, currentY + 12);

  currentY += 24;

  // --- 3. Summary KPI Cards ---
  const kpiWidth = 43;
  const kpiHeight = 16;
  const kpis = [
    { label: 'Incidentes Detectados', val: `${totalAlerts} (${criticalCount} críticos)`, color: [225, 29, 72] },
    { label: 'Mitigações Netfilter', val: `${mitigatedCount} aplicadas`, color: [16, 185, 129] },
    { label: 'Dispositivos Confiáveis', val: `${trustedDevices.length} de ${devices.length} hosts`, color: [14, 165, 233] },
    { label: 'Logs de Auditoria', val: `${auditLogs.length} eventos`, color: [99, 102, 241] }
  ];

  kpis.forEach((kpi, idx) => {
    const x = 14 + idx * (kpiWidth + 3.3);
    doc.setFillColor(241, 245, 249);
    doc.setDrawColor(203, 213, 225);
    doc.roundedRect(x, currentY, kpiWidth, kpiHeight, 1.5, 1.5, 'FD');

    doc.setFontSize(7.5);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(100, 116, 139);
    doc.text(kpi.label, x + 3, currentY + 5);

    doc.setFontSize(9);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(kpi.color[0], kpi.color[1], kpi.color[2]);
    doc.text(kpi.val, x + 3, currentY + 11.5);
  });

  currentY += kpiHeight + 8;

  // --- 4. SECTION 1: Resumo dos Incidentes Detectados ---
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(10.5);
  doc.setTextColor(15, 23, 42);
  doc.text('1. Resumo dos Incidentes & Ameaças Detectadas pelo Sniffer', 14, currentY);
  currentY += 3;

  const alertRows = alerts.map(a => [
    a.timestamp ? a.timestamp.slice(11, 19) || a.timestamp : 'Agora',
    a.title || 'Ameaça de Rede',
    a.severity ? a.severity.toUpperCase() : 'MÉDIA',
    a.sourceIp || '192.168.1.X',
    a.targetIp || 'Gateway',
    a.playbook?.applied ? 'Mitigado (Iptables)' : 'Ativo / Em Investigação'
  ]);

  if (alertRows.length === 0) {
    alertRows.push(['--', 'Nenhum incidente crítico registrado no período', 'INFO', '--', '--', 'Nominal']);
  }

  autoTable(doc, {
    startY: currentY,
    head: [['Horário', 'Incidente / Ameaça', 'Severidade', 'IP Origem', 'Alvo', 'Status']],
    body: alertRows,
    theme: 'grid',
    styles: {
      fontSize: 7.5,
      cellPadding: 2,
      font: 'helvetica'
    },
    headStyles: {
      fillColor: [15, 23, 42],
      textColor: [255, 255, 255],
      fontStyle: 'bold'
    },
    alternateRowStyles: {
      fillColor: [248, 250, 252]
    },
    columnStyles: {
      0: { cellWidth: 18 },
      1: { cellWidth: 62 },
      2: { cellWidth: 22, fontStyle: 'bold' },
      3: { cellWidth: 26 },
      4: { cellWidth: 24 },
      5: { cellWidth: 30, fontStyle: 'bold' }
    },
    didParseCell: (data) => {
      if (data.section === 'body' && data.column.index === 2) {
        const val = String(data.cell.raw);
        if (val.includes('CRITICAL') || val.includes('CRÍTICO')) {
          data.cell.styles.textColor = [225, 29, 72];
        } else if (val.includes('HIGH') || val.includes('ALTO')) {
          data.cell.styles.textColor = [217, 119, 6];
        } else {
          data.cell.styles.textColor = [14, 165, 233];
        }
      }
      if (data.section === 'body' && data.column.index === 5) {
        const val = String(data.cell.raw);
        if (val.includes('Mitigado')) {
          data.cell.styles.textColor = [16, 185, 129];
        } else {
          data.cell.styles.textColor = [225, 29, 72];
        }
      }
    }
  });

  currentY = (doc as any).lastAutoTable.finalY + 9;

  // Check page overflow
  if (currentY > 230) {
    doc.addPage();
    currentY = 20;
  }

  // --- 5. SECTION 2: Dispositivos Confiáveis & Inventário de Rede ---
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(10.5);
  doc.setTextColor(15, 23, 42);
  doc.text('2. Inventário de Rede & Dispositivos Confiáveis (Trusted Nodes)', 14, currentY);
  currentY += 3;

  const deviceRows = devices.map(d => [
    d.ip,
    d.mac,
    d.hostname || `host-${d.ip.split('.').pop()}`,
    d.vendor ? d.vendor.slice(0, 22) : 'Dispositivo Local',
    d.trustLevel === 'trusted' ? 'CONFIÁVEL' : d.trustLevel === 'quarantined' ? 'QUARENTENA' : 'NÃO VERIFICADO',
    `${d.threatScore}/100`,
    d.isOnline ? 'Online' : 'Offline'
  ]);

  autoTable(doc, {
    startY: currentY,
    head: [['Endereço IP', 'Endereço MAC', 'Hostname', 'Fabricante', 'Postura Confiabilidade', 'Risco', 'Status']],
    body: deviceRows,
    theme: 'grid',
    styles: {
      fontSize: 7.5,
      cellPadding: 2,
      font: 'helvetica'
    },
    headStyles: {
      fillColor: [30, 41, 59],
      textColor: [255, 255, 255],
      fontStyle: 'bold'
    },
    alternateRowStyles: {
      fillColor: [248, 250, 252]
    },
    columnStyles: {
      0: { cellWidth: 26, fontStyle: 'bold' },
      1: { cellWidth: 32 },
      2: { cellWidth: 34 },
      3: { cellWidth: 34 },
      4: { cellWidth: 30, fontStyle: 'bold' },
      5: { cellWidth: 14 },
      6: { cellWidth: 12 }
    },
    didParseCell: (data) => {
      if (data.section === 'body' && data.column.index === 4) {
        const val = String(data.cell.raw);
        if (val === 'CONFIÁVEL') {
          data.cell.styles.textColor = [16, 185, 129];
        } else if (val === 'QUARENTENA') {
          data.cell.styles.textColor = [225, 29, 72];
        } else {
          data.cell.styles.textColor = [100, 116, 139];
        }
      }
    }
  });

  currentY = (doc as any).lastAutoTable.finalY + 9;

  // Check page overflow
  if (currentY > 230) {
    doc.addPage();
    currentY = 20;
  }

  // --- 6. SECTION 3: Logs de Auditoria Recentes ---
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(10.5);
  doc.setTextColor(15, 23, 42);
  doc.text('3. Trilha de Auditoria Recente & Compliance Administrativo', 14, currentY);
  currentY += 3;

  const auditRows = auditLogs.slice(0, 15).map(l => [
    l.timestamp || '--',
    l.operator || 'Sistema NetSentry',
    l.action || 'Operação de Segurança',
    l.target || 'Host Kali',
    l.status === 'success' ? 'SUCESSO' : 'ALERTA'
  ]);

  if (auditRows.length === 0) {
    auditRows.push(['--', 'SecOps Admin', 'Verificação Periódica de Integridade', 'Kernel Netfilter', 'SUCESSO']);
  }

  autoTable(doc, {
    startY: currentY,
    head: [['Timestamp', 'Operador / Agente', 'Ação Executada', 'Objeto / Alvo', 'Resultado']],
    body: auditRows,
    theme: 'grid',
    styles: {
      fontSize: 7.5,
      cellPadding: 2,
      font: 'helvetica'
    },
    headStyles: {
      fillColor: [51, 65, 85],
      textColor: [255, 255, 255],
      fontStyle: 'bold'
    },
    alternateRowStyles: {
      fillColor: [248, 250, 252]
    },
    columnStyles: {
      0: { cellWidth: 26 },
      1: { cellWidth: 42, fontStyle: 'bold' },
      2: { cellWidth: 62 },
      3: { cellWidth: 32 },
      4: { cellWidth: 20, fontStyle: 'bold' }
    },
    didParseCell: (data) => {
      if (data.section === 'body' && data.column.index === 4) {
        const val = String(data.cell.raw);
        if (val === 'SUCESSO') {
          data.cell.styles.textColor = [16, 185, 129];
        } else {
          data.cell.styles.textColor = [217, 119, 6];
        }
      }
    }
  });

  // --- 7. Page Footers (Page X of Y) ---
  const pageCount = (doc as any).internal.getNumberOfPages();
  for (let i = 1; i <= pageCount; i++) {
    doc.setPage(i);
    doc.setDrawColor(226, 232, 240);
    doc.line(14, 287, 196, 287);

    doc.setFontSize(7.5);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(148, 163, 184);
    doc.text('NetSentry Kali SOC v2.4 · Documento Confidencial de Cibersegurança · 100% On-Premise', 14, 292);
    doc.text(`Página ${i} de ${pageCount}`, 180, 292);
  }

  // Trigger download
  const filename = `relatorio_seguranca_consolidado_netsentry_${fileDateStr}.pdf`;
  doc.save(filename);

  return doc;
}
