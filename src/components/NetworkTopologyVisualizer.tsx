import React, { useEffect, useRef, useState, useMemo, useCallback } from 'react';
import * as d3 from 'd3';
import { 
  NetworkDevice, 
  OpenPort, 
  EquipmentProfile, 
  NetworkDiagnosticResult,
  DeviceType,
  DeviceTrustLevel
} from '../types';
import { 
  Network, 
  Server, 
  ShieldAlert, 
  ShieldCheck, 
  Terminal, 
  Search, 
  ZoomIn, 
  ZoomOut, 
  Maximize2, 
  Minimize2, 
  RotateCcw, 
  Zap, 
  Filter, 
  Layers, 
  Cpu, 
  Activity, 
  Wifi, 
  AlertTriangle, 
  X, 
  Copy, 
  Check, 
  Sparkles, 
  Eye, 
  EyeOff, 
  Laptop, 
  HardDrive,
  Info
} from 'lucide-react';

// D3 Node & Link Interfaces
export interface TopologyNode extends d3.SimulationNodeDatum {
  id: string;
  ip: string;
  mac: string;
  hostname: string;
  vendor: string;
  deviceType: DeviceType | 'core_switch' | 'rogue_dhcp' | 'kali_node';
  trustLevel: DeviceTrustLevel;
  threatScore: number;
  openPorts: OpenPort[];
  isGateway?: boolean;
  isRogue?: boolean;
  isKali?: boolean;
  isInfra?: boolean;
  brand?: string;
  model?: string;
  discoveryMethod?: string;
  rxBytes?: number;
  txBytes?: number;
  packetCount?: number;
  lastSeen?: string;
  notes?: string;
  // Hierarchical level
  tier: number; // 0: Gateway, 1: Core Switch, 2: Infrastructure/AP, 3: Hosts/Endpoints, 4: Rogue
  radius: number;
}

export interface TopologyLink extends d3.SimulationLinkDatum<TopologyNode> {
  id: string;
  source: string | TopologyNode;
  target: string | TopologyNode;
  linkType: 'uplink' | 'access' | 'monitoring' | 'rogue' | 'trunk';
  latencyMs?: number;
  isThreat?: boolean;
}

export type TopologyLayoutMode = 'force' | 'hierarchical' | 'orbital';

interface NetworkTopologyVisualizerProps {
  devices?: NetworkDevice[];
  profiles?: EquipmentProfile[];
  diagResult?: NetworkDiagnosticResult | null;
  onOpenKaliTerminal?: (cmd: string) => void;
  onOpenAIForensic?: (type: 'device', device: NetworkDevice) => void;
  onScanSubnet?: (deep?: boolean) => void;
  onToast?: (msg: string, type?: 'success' | 'alert') => void;
  className?: string;
}

export const NetworkTopologyVisualizer: React.FC<NetworkTopologyVisualizerProps> = ({
  devices = [],
  profiles = [],
  diagResult = null,
  onOpenKaliTerminal,
  onOpenAIForensic,
  onScanSubnet,
  onToast,
  className = ''
}) => {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const svgRef = useRef<SVGSVGElement | null>(null);
  const zoomBehaviorRef = useRef<d3.ZoomBehavior<SVGSVGElement, unknown> | null>(null);
  const simulationRef = useRef<d3.Simulation<TopologyNode, TopologyLink> | null>(null);

  // UI Interactive States
  const [layoutMode, setLayoutMode] = useState<TopologyLayoutMode>('force');
  const [filterCategory, setFilterCategory] = useState<'all' | 'ports' | 'threats' | 'infra' | 'servers'>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [showPortBadges, setShowPortBadges] = useState(true);
  const [showNodeLabels, setShowNodeLabels] = useState(true);
  const [animatePackets, setAnimatePackets] = useState(true);
  const [selectedNode, setSelectedNode] = useState<TopologyNode | null>(null);
  const [hoveredNode, setHoveredNode] = useState<TopologyNode | null>(null);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [isScanning, setIsScanning] = useState(false);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [lastScanTimestamp, setLastScanTimestamp] = useState<string>(() => new Date().toLocaleTimeString('pt-BR'));

  // Copy helper
  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
    if (onToast) onToast(`Copiado para a área de transferência: ${text}`, 'success');
  };

  // Build Topology Graph from Devices, Profiles & Nmap Scans
  const { nodes, links } = useMemo(() => {
    const nodeList: TopologyNode[] = [];
    const linkList: TopologyLink[] = [];
    const nodeMap = new Map<string, TopologyNode>();

    const defaultGatewayIp = diagResult?.routingHealth?.defaultGateway || '192.168.0.1';

    // 1. Gateway Node (Root Tier 0)
    const gatewayNode: TopologyNode = {
      id: `node-${defaultGatewayIp}`,
      ip: defaultGatewayIp,
      mac: '50:c7:bf:41:2a:01',
      hostname: 'Gateway-Router.lan',
      vendor: 'TP-Link / Cisco Gateway',
      deviceType: 'gateway',
      trustLevel: 'trusted',
      threatScore: 0,
      openPorts: [
        { port: 53, service: 'DNS (Dnsmasq)', risk: 'low', version: '2.85' },
        { port: 80, service: 'HTTP (Router WebUI)', risk: 'medium', version: 'lighttpd' },
        { port: 443, service: 'HTTPS (Management SSL)', risk: 'low', version: 'TLSv1.3' }
      ],
      isGateway: true,
      tier: 0,
      radius: 26,
      notes: 'Gateway primário e servidor DNS local da LAN.'
    };
    nodeList.push(gatewayNode);
    nodeMap.set(gatewayNode.ip, gatewayNode);
    nodeMap.set(gatewayNode.id, gatewayNode);

    // 2. Core Infrastructure Switches / Firewalls from Profiles or Default
    if (profiles.length > 0) {
      profiles.forEach((prof, idx) => {
        const ip = prof.expectedIp || `192.168.0.${2 + idx}`;
        if (!nodeMap.has(ip)) {
          const infraNode: TopologyNode = {
            id: `prof-${prof.id}`,
            ip,
            mac: `00:0c:e7:${(10 + idx).toString(16)}:4a:${(20 + idx).toString(16)}`,
            hostname: prof.name,
            vendor: prof.brand ? prof.brand.toUpperCase() : 'Cisco Systems',
            deviceType: 'core_switch',
            trustLevel: 'trusted',
            threatScore: 0,
            openPorts: [
              { port: 22, service: 'SSH-2.0-OpenSSH', risk: 'low', version: '8.4' },
              { port: 161, service: 'SNMPv3', risk: 'low', version: 'AES-128' },
              { port: 443, service: 'HTTPS Mgmt', risk: 'low' }
            ],
            isInfra: true,
            brand: prof.brand,
            model: prof.model,
            tier: 1,
            radius: 22,
            notes: `Equipamento de infraestrutura gerenciado: ${prof.model}`
          };
          nodeList.push(infraNode);
          nodeMap.set(ip, infraNode);
          nodeMap.set(infraNode.id, infraNode);

          // Link to Gateway
          linkList.push({
            id: `link-gw-${infraNode.id}`,
            source: gatewayNode.id,
            target: infraNode.id,
            linkType: 'trunk',
            latencyMs: 1
          });
        }
      });
    } else {
      // Default Switch Core
      const defaultSwitch: TopologyNode = {
        id: 'node-switch-core',
        ip: '192.168.0.2',
        mac: '00:0c:e7:3f:81:aa',
        hostname: 'Cisco-SG350-Core',
        vendor: 'Cisco Systems',
        deviceType: 'core_switch',
        trustLevel: 'trusted',
        threatScore: 0,
        openPorts: [
          { port: 22, service: 'SSH (Cisco IOS)', risk: 'low' },
          { port: 161, service: 'SNMPv3 Agent', risk: 'low' }
        ],
        isInfra: true,
        brand: 'cisco',
        model: 'SG350-28P Managed',
        tier: 1,
        radius: 22,
        notes: 'Switch Core Gigabit com VLANs e DHCP Snooping.'
      };
      nodeList.push(defaultSwitch);
      nodeMap.set(defaultSwitch.ip, defaultSwitch);
      nodeMap.set(defaultSwitch.id, defaultSwitch);

      linkList.push({
        id: 'link-gw-switch',
        source: gatewayNode.id,
        target: defaultSwitch.id,
        linkType: 'trunk',
        latencyMs: 1
      });
    }

    // Reference switch for downstream endpoint attachments
    const coreSwitch = nodeList.find(n => n.deviceType === 'core_switch') || gatewayNode;

    // 3. Kali Linux SOC Auditor Node
    const kaliIp = '192.168.0.156';
    const kaliNode: TopologyNode = {
      id: `node-${kaliIp}`,
      ip: kaliIp,
      mac: '08:00:27:fa:41:89',
      hostname: 'Kali-SOC-Agent.local',
      vendor: 'Kali Linux Rolling (Security Host)',
      deviceType: 'kali_node',
      trustLevel: 'trusted',
      threatScore: 0,
      openPorts: [
        { port: 22, service: 'OpenSSH (Kali)', risk: 'low', version: '9.3p1' },
        { port: 3000, service: 'HTTP (NetSentry React Dashboard)', risk: 'low' },
        { port: 8080, service: 'HTTP (NetSentry Scapy Daemon)', risk: 'low' },
        { port: 5432, service: 'PostgreSQL 16 DB', risk: 'low' }
      ],
      isKali: true,
      tier: 1,
      radius: 24,
      notes: 'Host do Analista de Segurança / Kali Linux com Sniffer Scapy e motor Nmap.'
    };
    nodeList.push(kaliNode);
    nodeMap.set(kaliIp, kaliNode);
    nodeMap.set(kaliNode.id, kaliNode);

    linkList.push({
      id: `link-${coreSwitch.id}-${kaliNode.id}`,
      source: coreSwitch.id,
      target: kaliNode.id,
      linkType: 'monitoring',
      latencyMs: 1
    });

    // 4. Rogue DHCP Server (if detected in Network Audit)
    if (diagResult?.dhcpServersFound && diagResult.dhcpServersFound.length > 1) {
      const rogue = diagResult.dhcpServersFound.find(d => !d.isAuthorized || d.ip !== defaultGatewayIp);
      if (rogue) {
        const rogueNode: TopologyNode = {
          id: `node-rogue-${rogue.ip}`,
          ip: rogue.ip,
          mac: rogue.mac || '00:1a:2b:ff:ee:01',
          hostname: 'Rogue-DHCP-Intruder',
          vendor: 'Desconhecido / Roteador Não Autorizado',
          deviceType: 'rogue_dhcp',
          trustLevel: 'blocked',
          threatScore: 98,
          openPorts: [
            { port: 67, service: 'DHCP Offer (Rogue Server)', risk: 'critical', version: 'dnsmasq' },
            { port: 80, service: 'HTTP WebUI', risk: 'high' }
          ],
          isRogue: true,
          tier: 4,
          radius: 25,
          notes: 'Servidor DHCP concorrente não autorizado distribuindo gateways forjados!'
        };
        nodeList.push(rogueNode);
        nodeMap.set(rogue.ip, rogueNode);
        nodeMap.set(rogueNode.id, rogueNode);

        linkList.push({
          id: `link-rogue-${rogueNode.id}`,
          source: coreSwitch.id,
          target: rogueNode.id,
          linkType: 'rogue',
          latencyMs: 3,
          isThreat: true
        });
      }
    }

    // 5. Populate Discovered Devices (Nmap & ARP)
    const defaultDevices: NetworkDevice[] = [
      {
        id: 'dev-srv-ad',
        ip: '192.168.0.10',
        mac: '00:50:56:a1:b2:c3',
        hostname: 'SRV-DC01.corp.local',
        vendor: 'VMware Virtual Platform',
        deviceType: 'server',
        trustLevel: 'trusted',
        openPorts: [
          { port: 53, service: 'DNS Active Directory', risk: 'low' },
          { port: 88, service: 'Kerberos KDC', risk: 'low' },
          { port: 135, service: 'msrpc', risk: 'medium' },
          { port: 389, service: 'LDAP Microsoft', risk: 'medium' },
          { port: 445, service: 'microsoft-ds (SMB)', risk: 'high', cve: 'MS17-010 audit' },
          { port: 3389, service: 'ms-wbt-server (RDP)', risk: 'medium' }
        ],
        rxBytes: 450200,
        txBytes: 890400,
        packetCount: 3410,
        threatScore: 12,
        firstSeen: 'Hoje 08:00',
        lastSeen: 'Agora (Nmap)',
        isOnline: true,
        discoveryMethod: 'dns'
      },
      {
        id: 'dev-nas-backup',
        ip: '192.168.0.20',
        mac: '00:11:32:89:fe:42',
        hostname: 'Synology-DS920',
        vendor: 'Synology NAS System',
        deviceType: 'server',
        trustLevel: 'trusted',
        openPorts: [
          { port: 80, service: 'HTTP (Synology DSM)', risk: 'medium' },
          { port: 443, service: 'HTTPS (DSM WebUI)', risk: 'low' },
          { port: 445, service: 'SMB/CIFS Share', risk: 'medium' },
          { port: 2049, service: 'NFS Network File System', risk: 'low' }
        ],
        rxBytes: 12400000,
        txBytes: 5200000,
        packetCount: 15400,
        threatScore: 8,
        firstSeen: 'Hoje 08:00',
        lastSeen: 'Agora (Nmap)',
        isOnline: true,
        discoveryMethod: 'netbios'
      },
      {
        id: 'dev-ws-analyst',
        ip: '192.168.0.45',
        mac: '00:14:22:78:90:ab',
        hostname: 'WS-THALES-DELL',
        vendor: 'Dell Inc. Workstation',
        deviceType: 'workstation',
        trustLevel: 'trusted',
        openPorts: [
          { port: 135, service: 'msrpc Windows', risk: 'low' },
          { port: 445, service: 'SMB File Sharing', risk: 'low' }
        ],
        rxBytes: 890000,
        txBytes: 310000,
        packetCount: 2200,
        threatScore: 5,
        firstSeen: 'Hoje 08:15',
        lastSeen: 'Agora (Nmap)',
        isOnline: true,
        discoveryMethod: 'netbios'
      },
      {
        id: 'dev-iot-cam',
        ip: '192.168.0.78',
        mac: '24:0a:c4:33:11:ff',
        hostname: 'IP-CAM-RECEPTION',
        vendor: 'Espressif (ESP32 IoT)',
        deviceType: 'iot',
        trustLevel: 'unverified',
        openPorts: [
          { port: 80, service: 'HTTP Web Stream', risk: 'high', version: 'Boa 0.94' },
          { port: 554, service: 'RTSP Video Feed (Unencrypted)', risk: 'high' }
        ],
        rxBytes: 120000,
        txBytes: 4500000,
        packetCount: 8900,
        threatScore: 42,
        firstSeen: 'Hoje 08:20',
        lastSeen: 'Agora (Nmap)',
        isOnline: true,
        discoveryMethod: 'arp'
      },
      {
        id: 'dev-guest-mobile',
        ip: '192.168.0.112',
        mac: '3c:22:fb:99:43:12',
        hostname: 'iPhone-Visitante',
        vendor: 'Apple Inc. (iOS)',
        deviceType: 'workstation',
        trustLevel: 'unverified',
        openPorts: [],
        rxBytes: 89000,
        txBytes: 45000,
        packetCount: 310,
        threatScore: 15,
        firstSeen: 'Hoje 09:10',
        lastSeen: 'Agora (ARP)',
        isOnline: true,
        discoveryMethod: 'arp'
      }
    ];

    const baseDevices: NetworkDevice[] = devices.length > 0 ? devices : defaultDevices;

    baseDevices.forEach((dev, idx) => {
      // Don't duplicate if already added as gateway or kali
      if (dev.ip === defaultGatewayIp || dev.ip === kaliIp || nodeMap.has(dev.ip)) {
        return;
      }

      const isServer = dev.deviceType === 'server';
      const isHighThreat = (dev.threatScore || 0) >= 50;
      
      const endpointNode: TopologyNode = {
        id: dev.id || `node-${dev.ip}`,
        ip: dev.ip,
        mac: dev.mac,
        hostname: dev.customAlias || dev.hostname || `Host-${dev.ip.split('.').pop()}`,
        vendor: dev.vendor || 'Dispositivo de Rede',
        deviceType: dev.deviceType,
        trustLevel: dev.trustLevel,
        threatScore: dev.threatScore || 0,
        openPorts: dev.openPorts || [],
        tier: isServer ? 2 : 3,
        radius: isServer ? 20 : 16,
        rxBytes: dev.rxBytes,
        txBytes: dev.txBytes,
        packetCount: dev.packetCount,
        lastSeen: dev.lastSeen || 'Agora (Nmap)',
        discoveryMethod: dev.discoveryMethod,
        notes: dev.notes
      };

      nodeList.push(endpointNode);
      nodeMap.set(dev.ip, endpointNode);
      nodeMap.set(endpointNode.id, endpointNode);

      // Link endpoint to Core Switch
      linkList.push({
        id: `link-${coreSwitch.id}-${endpointNode.id}`,
        source: coreSwitch.id,
        target: endpointNode.id,
        linkType: isServer ? 'uplink' : 'access',
        latencyMs: isServer ? 1 : 2 + (idx % 3),
        isThreat: isHighThreat
      });
    });

    return { nodes: nodeList, links: linkList };
  }, [devices, profiles, diagResult]);

  // Filtered Nodes & Links based on Search and Category
  const { filteredNodes, filteredLinks } = useMemo(() => {
    let activeNodes = [...nodes];

    // Category Filter
    if (filterCategory === 'ports') {
      activeNodes = activeNodes.filter(n => n.openPorts.length > 0 || n.isGateway);
    } else if (filterCategory === 'threats') {
      activeNodes = activeNodes.filter(n => n.threatScore >= 30 || n.isRogue || n.trustLevel === 'quarantined' || n.trustLevel === 'blocked');
    } else if (filterCategory === 'infra') {
      activeNodes = activeNodes.filter(n => n.isGateway || n.isInfra || n.deviceType === 'core_switch' || n.isKali);
    } else if (filterCategory === 'servers') {
      activeNodes = activeNodes.filter(n => n.deviceType === 'server' || n.isGateway);
    }

    // Search Query Filter
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase().trim();
      activeNodes = activeNodes.filter(n => 
        n.ip.toLowerCase().includes(q) ||
        n.hostname.toLowerCase().includes(q) ||
        n.mac.toLowerCase().includes(q) ||
        n.vendor.toLowerCase().includes(q) ||
        n.openPorts.some(p => p.service.toLowerCase().includes(q) || p.port.toString().includes(q))
      );
      // Ensure Gateway is kept if anything matches so graph remains connected
      const gw = nodes.find(n => n.isGateway);
      if (gw && !activeNodes.some(n => n.id === gw.id) && activeNodes.length > 0) {
        activeNodes.unshift(gw);
      }
    }

    const activeNodeIds = new Set(activeNodes.map(n => n.id));
    const activeLinks = links.filter(l => {
      const srcId = typeof l.source === 'object' ? l.source.id : l.source;
      const tgtId = typeof l.target === 'object' ? l.target.id : l.target;
      return activeNodeIds.has(srcId) && activeNodeIds.has(tgtId);
    });

    return { filteredNodes: activeNodes, filteredLinks: activeLinks };
  }, [nodes, links, filterCategory, searchQuery]);

  // Color helper according to role & threat level
  const getNodeColor = useCallback((node: TopologyNode) => {
    if (node.isRogue) return { fill: '#e11d48', stroke: '#fb7185', glow: 'rgba(225, 29, 72, 0.6)' }; // Crimson Red
    if (node.isGateway) return { fill: '#06b6d4', stroke: '#22d3ee', glow: 'rgba(6, 182, 212, 0.5)' }; // Cyan
    if (node.isKali) return { fill: '#8b5cf6', stroke: '#a78bfa', glow: 'rgba(139, 92, 246, 0.5)' }; // Violet
    if (node.isInfra || node.deviceType === 'core_switch') return { fill: '#3b82f6', stroke: '#60a5fa', glow: 'rgba(59, 130, 246, 0.5)' }; // Blue
    if (node.deviceType === 'server') return { fill: '#10b981', stroke: '#34d399', glow: 'rgba(16, 185, 129, 0.4)' }; // Emerald Green
    if (node.threatScore >= 60) return { fill: '#f43f5e', stroke: '#fb7185', glow: 'rgba(244, 63, 94, 0.5)' };
    if (node.threatScore >= 30) return { fill: '#f59e0b', stroke: '#fbbf24', glow: 'rgba(245, 158, 11, 0.4)' };
    return { fill: '#1e293b', stroke: '#475569', glow: 'rgba(71, 85, 105, 0.3)' }; // Slate Dark
  }, []);

  // Trigger Nmap rescan
  const handleTriggerNmapScan = () => {
    setIsScanning(true);
    if (onScanSubnet) {
      onScanSubnet(true);
    }
    setTimeout(() => {
      setIsScanning(false);
      setLastScanTimestamp(new Date().toLocaleTimeString('pt-BR'));
      if (onToast) onToast('Varredura Nmap da sub-rede finalizada. Topologia atualizada!', 'success');
    }, 3500);
  };

  // Reset Zoom
  const handleResetZoom = () => {
    if (!svgRef.current || !zoomBehaviorRef.current) return;
    const svg = d3.select(svgRef.current);
    svg.transition().duration(750).call(
      zoomBehaviorRef.current.transform,
      d3.zoomIdentity
    );
  };

  const handleZoomIn = () => {
    if (!svgRef.current || !zoomBehaviorRef.current) return;
    d3.select(svgRef.current).transition().duration(300).call(zoomBehaviorRef.current.scaleBy, 1.3);
  };

  const handleZoomOut = () => {
    if (!svgRef.current || !zoomBehaviorRef.current) return;
    d3.select(svgRef.current).transition().duration(300).call(zoomBehaviorRef.current.scaleBy, 0.7);
  };

  // D3 Force Simulation & Rendering Pipeline
  useEffect(() => {
    if (!svgRef.current || !containerRef.current) return;

    const width = containerRef.current.clientWidth || 900;
    const height = isFullscreen ? window.innerHeight - 140 : 540;

    const svg = d3.select(svgRef.current)
      .attr('width', width)
      .attr('height', height)
      .attr('viewBox', [0, 0, width, height]);

    svg.selectAll('*').remove();

    // Defs: Filters, Gradients, Marker Arrows
    const defs = svg.append('defs');

    // Glow Filter
    const filter = defs.append('filter')
      .attr('id', 'topo-glow')
      .attr('x', '-50%')
      .attr('y', '-50%')
      .attr('width', '200%')
      .attr('height', '200%');
    filter.append('feGaussianBlur').attr('stdDeviation', '4').attr('result', 'coloredBlur');
    const feMerge = filter.append('feMerge');
    feMerge.append('feMergeNode').attr('in', 'coloredBlur');
    feMerge.append('feMergeNode').attr('in', 'SourceGraphic');

    // Threat Pulsing Glow
    const threatFilter = defs.append('filter')
      .attr('id', 'threat-glow')
      .attr('x', '-50%')
      .attr('y', '-50%')
      .attr('width', '200%')
      .attr('height', '200%');
    threatFilter.append('feGaussianBlur').attr('stdDeviation', '6').attr('result', 'blur');
    const threatMerge = threatFilter.append('feMerge');
    threatMerge.append('feMergeNode').attr('in', 'blur');
    threatMerge.append('feMergeNode').attr('in', 'SourceGraphic');

    // Background Grid Pattern
    const pattern = defs.append('pattern')
      .attr('id', 'topo-grid')
      .attr('width', 30)
      .attr('height', 30)
      .attr('patternUnits', 'userSpaceOnUse');
    pattern.append('path')
      .attr('d', 'M 30 0 L 0 0 0 30')
      .attr('fill', 'none')
      .attr('stroke', '#1e293b')
      .attr('stroke-width', '0.7')
      .attr('stroke-opacity', '0.4');

    // Background rect
    svg.append('rect')
      .attr('width', '100%')
      .attr('height', '100%')
      .attr('fill', '#070b14');

    svg.append('rect')
      .attr('width', '100%')
      .attr('height', '100%')
      .attr('fill', 'url(#topo-grid)');

    // Main Zoomable Container Group
    const g = svg.append('g').attr('class', 'topology-main-group');

    // Setup Zoom Behavior
    const zoom = d3.zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.3, 3])
      .on('zoom', (event) => {
        g.attr('transform', event.transform);
      });
    zoomBehaviorRef.current = zoom;
    svg.call(zoom);

    // Deep clone data for D3 mutation
    const simNodes: TopologyNode[] = filteredNodes.map(d => ({ ...d }));
    const simLinks: TopologyLink[] = filteredLinks.map(l => ({
      ...l,
      source: typeof l.source === 'object' ? l.source.id : l.source,
      target: typeof l.target === 'object' ? l.target.id : l.target
    }));

    // Setup D3 Simulation
    const simulation = d3.forceSimulation<TopologyNode>(simNodes);
    simulationRef.current = simulation;

    // Apply layout-specific forces
    if (layoutMode === 'orbital') {
      // Concentric Rings around Gateway
      simulation
        .force('link', d3.forceLink<TopologyNode, TopologyLink>(simLinks).id(d => d.id).distance(120))
        .force('charge', d3.forceManyBody().strength(-280))
        .force('collide', d3.forceCollide().radius(d => (d as TopologyNode).radius + 18))
        .force('center', d3.forceCenter(width / 2, height / 2))
        .force('r', d3.forceRadial(
          (d) => {
            const node = d as TopologyNode;
            if (node.isGateway) return 0;
            if (node.isInfra || node.isKali) return 130;
            if (node.deviceType === 'server') return 210;
            if (node.isRogue) return 290;
            return 280;
          },
          width / 2,
          height / 2
        ).strength(0.8));
    } else if (layoutMode === 'hierarchical') {
      // Tree / Hierarchical Force by Tier (Y-axis separation)
      simulation
        .force('link', d3.forceLink<TopologyNode, TopologyLink>(simLinks).id(d => d.id).distance(80))
        .force('charge', d3.forceManyBody().strength(-340))
        .force('collide', d3.forceCollide().radius(d => (d as TopologyNode).radius + 24))
        .force('x', d3.forceX(width / 2).strength(0.2))
        .force('y', d3.forceY((d) => {
          const node = d as TopologyNode;
          const tierPositions = [80, 190, 310, 420, 470];
          return tierPositions[node.tier] || 300;
        }).strength(0.9));
    } else {
      // Organic Force-Directed Layout
      simulation
        .force('link', d3.forceLink<TopologyNode, TopologyLink>(simLinks).id(d => d.id).distance(d => {
          if (d.linkType === 'trunk') return 110;
          if (d.linkType === 'monitoring') return 100;
          if (d.linkType === 'rogue') return 150;
          return 90;
        }))
        .force('charge', d3.forceManyBody().strength(-400))
        .force('center', d3.forceCenter(width / 2, height / 2))
        .force('collide', d3.forceCollide().radius(d => (d as TopologyNode).radius + 22));
    }

    // Links Layer
    const linkGroup = g.append('g').attr('class', 'links');
    const linkElements = linkGroup.selectAll<SVGLineElement, TopologyLink>('line')
      .data(simLinks)
      .enter()
      .append('line')
      .attr('stroke', (d) => {
        if (d.linkType === 'rogue') return '#f43f5e';
        if (d.linkType === 'monitoring') return '#a78bfa';
        if (d.linkType === 'trunk') return '#38bdf8';
        return '#334155';
      })
      .attr('stroke-width', (d) => (d.linkType === 'trunk' || d.linkType === 'monitoring' ? 2.5 : 1.5))
      .attr('stroke-dasharray', (d) => (d.linkType === 'rogue' ? '5,4' : 'none'))
      .attr('stroke-opacity', 0.7);

    // Link packet flow particles (optional animation)
    let particleSelection: d3.Selection<SVGCircleElement, TopologyLink, SVGGElement, unknown> | null = null;
    if (animatePackets) {
      const particleGroup = g.append('g').attr('class', 'packet-particles');
      particleSelection = particleGroup.selectAll<SVGCircleElement, TopologyLink>('circle')
        .data(simLinks)
        .enter()
        .append('circle')
        .attr('r', d => (d.linkType === 'rogue' ? 3.5 : 2.5))
        .attr('fill', d => (d.linkType === 'rogue' ? '#f43f5e' : d.linkType === 'monitoring' ? '#c084fc' : '#38bdf8'))
        .attr('filter', 'url(#topo-glow)');
    }

    // Nodes Layer
    const nodeGroup = g.append('g').attr('class', 'nodes');
    const nodeElements = nodeGroup.selectAll<SVGGElement, TopologyNode>('g')
      .data(simNodes)
      .enter()
      .append('g')
      .attr('class', 'topology-node')
      .style('cursor', 'pointer')
      .call(
        d3.drag<SVGGElement, TopologyNode>()
          .on('start', (event, d) => {
            if (!event.active) simulation.alphaTarget(0.3).restart();
            d.fx = d.x;
            d.fy = d.y;
          })
          .on('drag', (event, d) => {
            d.fx = event.x;
            d.fy = event.y;
          })
          .on('end', (event, d) => {
            if (!event.active) simulation.alphaTarget(0);
            d.fx = null;
            d.fy = null;
          })
      );

    // Node Outer Pulsing Ring for Threats / Rogue
    nodeElements.each(function(d) {
      if (d.isRogue || d.threatScore >= 60) {
        d3.select(this).append('circle')
          .attr('r', d.radius + 8)
          .attr('fill', 'none')
          .attr('stroke', '#f43f5e')
          .attr('stroke-width', 1.5)
          .attr('stroke-opacity', 0.8)
          .attr('stroke-dasharray', '4,3')
          .attr('class', 'animate-pulse');
      }
    });

    // Node Primary Circle Base
    nodeElements.append('circle')
      .attr('r', d => d.radius)
      .attr('fill', d => getNodeColor(d).fill)
      .attr('stroke', d => getNodeColor(d).stroke)
      .attr('stroke-width', d => (d.isGateway || d.isKali || d.isRogue ? 2.5 : 1.8))
      .attr('filter', d => (d.isRogue ? 'url(#threat-glow)' : 'url(#topo-glow)'));

    // Node Center Icon / Graphic Badge
    nodeElements.append('text')
      .attr('text-anchor', 'middle')
      .attr('dominant-baseline', 'central')
      .attr('fill', '#f8fafc')
      .attr('font-size', d => (d.radius >= 22 ? '11px' : '9px'))
      .attr('font-family', 'monospace')
      .attr('font-weight', 'bold')
      .text(d => {
        if (d.isGateway) return 'GW';
        if (d.isKali) return 'KALI';
        if (d.isRogue) return 'ROGUE';
        if (d.isInfra) return 'SW';
        if (d.deviceType === 'server') return 'SRV';
        if (d.deviceType === 'iot') return 'IOT';
        return d.ip.split('.').pop() || 'H';
      });

    // Node Open Port Badge Counter (pill at top right of circle)
    if (showPortBadges) {
      const portBadges = nodeElements.filter(d => d.openPorts.length > 0);
      
      const badgeG = portBadges.append('g')
        .attr('transform', d => `translate(${d.radius * 0.7}, ${-d.radius * 0.7})`);

      badgeG.append('circle')
        .attr('r', 8)
        .attr('fill', d => (d.openPorts.some(p => p.risk === 'critical' || p.risk === 'high') ? '#e11d48' : '#0284c7'))
        .attr('stroke', '#0f172a')
        .attr('stroke-width', 1.5);

      badgeG.append('text')
        .attr('text-anchor', 'middle')
        .attr('dominant-baseline', 'central')
        .attr('fill', '#ffffff')
        .attr('font-size', '8px')
        .attr('font-weight', 'bold')
        .attr('font-family', 'monospace')
        .text(d => d.openPorts.length);
    }

    // Node Text Labels (IP & Hostname below node)
    if (showNodeLabels) {
      nodeElements.append('text')
        .attr('dy', d => d.radius + 13)
        .attr('text-anchor', 'middle')
        .attr('fill', '#e2e8f0')
        .attr('font-size', '10px')
        .attr('font-weight', '600')
        .attr('font-family', 'sans-serif')
        .text(d => d.hostname);

      nodeElements.append('text')
        .attr('dy', d => d.radius + 24)
        .attr('text-anchor', 'middle')
        .attr('fill', '#94a3b8')
        .attr('font-size', '9px')
        .attr('font-family', 'monospace')
        .text(d => d.ip);
    }

    // Interactivity: Hover & Click
    nodeElements
      .on('mouseenter', function(_event, d) {
        setHoveredNode(d);
        d3.select(this).select('circle')
          .transition()
          .duration(150)
          .attr('r', d.radius + 4)
          .attr('stroke-width', 3);
      })
      .on('mouseleave', function(_event, d) {
        setHoveredNode(null);
        d3.select(this).select('circle')
          .transition()
          .duration(150)
          .attr('r', d.radius)
          .attr('stroke-width', d.isGateway || d.isKali || d.isRogue ? 2.5 : 1.8);
      })
      .on('click', function(_event, d) {
        setSelectedNode(d);
      });

    // Particle animation progress variable
    let packetStep = 0;

    // Simulation Tick Listener
    simulation.on('tick', () => {
      linkElements
        .attr('x1', d => (d.source as TopologyNode).x || 0)
        .attr('y1', d => (d.source as TopologyNode).y || 0)
        .attr('x2', d => (d.target as TopologyNode).x || 0)
        .attr('y2', d => (d.target as TopologyNode).y || 0);

      nodeElements.attr('transform', d => `translate(${d.x || 0}, ${d.y || 0})`);

      if (particleSelection) {
        packetStep = (packetStep + 0.008) % 1;
        particleSelection.each(function(d) {
          const s = d.source as TopologyNode;
          const t = d.target as TopologyNode;
          if (s.x !== undefined && s.y !== undefined && t.x !== undefined && t.y !== undefined) {
            const x = s.x + (t.x - s.x) * packetStep;
            const y = s.y + (t.y - s.y) * packetStep;
            d3.select(this).attr('cx', x).attr('cy', y);
          }
        });
      }
    });

    return () => {
      simulation.stop();
    };
  }, [filteredNodes, filteredLinks, layoutMode, showPortBadges, showNodeLabels, animatePackets, isFullscreen, getNodeColor]);

  // Aggregate Metrics for Header HUD
  const totalOpenPorts = useMemo(() => {
    return filteredNodes.reduce((acc, n) => acc + (n.openPorts?.length || 0), 0);
  }, [filteredNodes]);

  const rogueCount = useMemo(() => {
    return filteredNodes.filter(n => n.isRogue).length;
  }, [filteredNodes]);

  const highThreatCount = useMemo(() => {
    return filteredNodes.filter(n => n.threatScore >= 50).length;
  }, [filteredNodes]);

  return (
    <div className={`relative rounded-xl bg-slate-900 border border-slate-800 shadow-xl overflow-hidden flex flex-col ${isFullscreen ? 'fixed inset-4 z-50 bg-slate-950 border-cyan-700' : ''} ${className}`}>
      
      {/* 1. Header Toolbar & Metric HUD */}
      <div className="p-4 bg-slate-950/90 border-b border-slate-800 flex flex-col xl:flex-row xl:items-center justify-between gap-3 shrink-0">
        <div className="flex items-center gap-3 flex-wrap">
          <div className="w-9 h-9 rounded-lg bg-cyan-950 border border-cyan-700 flex items-center justify-center text-cyan-400 shrink-0">
            <Network className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-sm font-bold text-slate-100">Topologia de Rede Interativa D3.js</h2>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800 font-bold">
                Nmap Topology Engine
              </span>
              {rogueCount > 0 && (
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-950 text-rose-300 border border-rose-700 font-bold animate-pulse flex items-center gap-1">
                  <AlertTriangle className="w-3 h-3" />
                  Rogue DHCP Detectado
                </span>
              )}
            </div>
            <p className="text-xs text-slate-400 flex items-center gap-2 mt-0.5">
              <span>Mapeamento de relacionamentos e portas abertas da varredura Nmap.</span>
              <span className="text-slate-600">·</span>
              <span className="text-[11px] font-mono text-slate-400">Último scan: <strong className="text-slate-200">{lastScanTimestamp}</strong></span>
            </p>
          </div>
        </div>

        {/* Action Controls & Rescan */}
        <div className="flex items-center gap-2 flex-wrap self-end xl:self-auto">
          {/* Layout Mode Selector */}
          <div className="flex items-center bg-slate-900 p-0.5 rounded-lg border border-slate-800 text-xs font-semibold">
            <button
              onClick={() => setLayoutMode('force')}
              className={`px-2.5 py-1 rounded transition-colors ${layoutMode === 'force' ? 'bg-cyan-500/20 text-cyan-300 font-bold' : 'text-slate-400 hover:text-slate-200'}`}
              title="Layout Força-Dirigida Dinâmica"
            >
              Orgânico
            </button>
            <button
              onClick={() => setLayoutMode('orbital')}
              className={`px-2.5 py-1 rounded transition-colors ${layoutMode === 'orbital' ? 'bg-cyan-500/20 text-cyan-300 font-bold' : 'text-slate-400 hover:text-slate-200'}`}
              title="Layout Concéntrico por Zonas / Órbitas"
            >
              Órbitas
            </button>
            <button
              onClick={() => setLayoutMode('hierarchical')}
              className={`px-2.5 py-1 rounded transition-colors ${layoutMode === 'hierarchical' ? 'bg-cyan-500/20 text-cyan-300 font-bold' : 'text-slate-400 hover:text-slate-200'}`}
              title="Layout Hierárquico / Árvore de Roteamento"
            >
              Hierarquia
            </button>
          </div>

          {/* Trigger Nmap Scan */}
          <button
            onClick={handleTriggerNmapScan}
            disabled={isScanning}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-cyan-400 hover:bg-cyan-300 disabled:opacity-60 text-slate-950 font-bold text-xs rounded-lg transition-all shadow-sm cursor-pointer"
          >
            <Zap className={`w-3.5 h-3.5 fill-slate-950 ${isScanning ? 'animate-spin' : ''}`} />
            <span>{isScanning ? 'Escanenado Nmap...' : 'Reescanear Nmap'}</span>
          </button>

          {/* Fullscreen Toggle */}
          <button
            onClick={() => setIsFullscreen(!isFullscreen)}
            className="p-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg transition-colors"
            title={isFullscreen ? 'Minimizar' : 'Tela Cheia'}
          >
            {isFullscreen ? <Minimize2 className="w-4 h-4" /> : <Maximize2 className="w-4 h-4" />}
          </button>
        </div>
      </div>

      {/* 2. Secondary Filter & Query Bar */}
      <div className="px-4 py-2.5 bg-slate-950/60 border-b border-slate-800/80 flex flex-col md:flex-row md:items-center justify-between gap-3 text-xs shrink-0">
        <div className="flex items-center gap-2 flex-wrap">
          {/* Search Box */}
          <div className="relative w-48 sm:w-60">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Filtrar por IP, host ou porta..."
              className="w-full pl-8 pr-3 py-1 bg-slate-900 border border-slate-700/80 rounded-lg text-slate-200 text-xs placeholder:text-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
            />
            {searchQuery && (
              <button 
                onClick={() => setSearchQuery('')}
                className="absolute right-2 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-200"
              >
                <X className="w-3 h-3" />
              </button>
            )}
          </div>

          {/* Category Filter Pills */}
          <div className="flex items-center gap-1 overflow-x-auto">
            <button
              onClick={() => setFilterCategory('all')}
              className={`px-2 py-0.5 rounded text-[11px] font-medium transition-colors ${filterCategory === 'all' ? 'bg-slate-800 text-slate-100 border border-slate-600' : 'text-slate-400 hover:text-slate-200'}`}
            >
              Todos ({nodes.length})
            </button>
            <button
              onClick={() => setFilterCategory('ports')}
              className={`px-2 py-0.5 rounded text-[11px] font-medium transition-colors ${filterCategory === 'ports' ? 'bg-cyan-950 text-cyan-300 border border-cyan-700' : 'text-slate-400 hover:text-slate-200'}`}
            >
              Com Portas Nmap ({nodes.filter(n => n.openPorts.length > 0).length})
            </button>
            <button
              onClick={() => setFilterCategory('threats')}
              className={`px-2 py-0.5 rounded text-[11px] font-medium transition-colors ${filterCategory === 'threats' ? 'bg-rose-950 text-rose-300 border border-rose-700' : 'text-slate-400 hover:text-slate-200'}`}
            >
              Ameaças / Rogue ({nodes.filter(n => n.threatScore >= 30 || n.isRogue).length})
            </button>
            <button
              onClick={() => setFilterCategory('infra')}
              className={`px-2 py-0.5 rounded text-[11px] font-medium transition-colors ${filterCategory === 'infra' ? 'bg-blue-950 text-blue-300 border border-blue-700' : 'text-slate-400 hover:text-slate-200'}`}
            >
              Infraestrutura ({nodes.filter(n => n.isGateway || n.isInfra || n.isKali).length})
            </button>
          </div>
        </div>

        {/* Display Toggles */}
        <div className="flex items-center gap-3 text-slate-400 text-[11px]">
          <label className="flex items-center gap-1.5 cursor-pointer hover:text-slate-200 select-none">
            <input
              type="checkbox"
              checked={showPortBadges}
              onChange={(e) => setShowPortBadges(e.target.checked)}
              className="rounded bg-slate-900 border-slate-700 text-cyan-500 focus:ring-0"
            />
            <span>Badges Nmap</span>
          </label>

          <label className="flex items-center gap-1.5 cursor-pointer hover:text-slate-200 select-none">
            <input
              type="checkbox"
              checked={animatePackets}
              onChange={(e) => setAnimatePackets(e.target.checked)}
              className="rounded bg-slate-900 border-slate-700 text-cyan-500 focus:ring-0"
            />
            <span>Pulsos de Tráfego</span>
          </label>
        </div>
      </div>

      {/* 3. D3 SVG Canvas Area */}
      <div 
        ref={containerRef}
        className="relative flex-1 w-full bg-[#070b14] overflow-hidden min-h-[460px]"
      >
        <svg 
          ref={svgRef} 
          className="w-full h-full block select-none"
        />

        {/* Floating Zoom & Center HUD Controls (Bottom-Left) */}
        <div className="absolute bottom-4 left-4 flex items-center gap-1 bg-slate-900/90 backdrop-blur-md p-1 rounded-lg border border-slate-800 shadow-lg text-slate-300">
          <button 
            onClick={handleZoomIn}
            className="p-1.5 hover:bg-slate-800 rounded text-slate-300 hover:text-slate-100 transition-colors"
            title="Aproximar (+)"
          >
            <ZoomIn className="w-4 h-4" />
          </button>
          <button 
            onClick={handleZoomOut}
            className="p-1.5 hover:bg-slate-800 rounded text-slate-300 hover:text-slate-100 transition-colors"
            title="Afastar (-)"
          >
            <ZoomOut className="w-4 h-4" />
          </button>
          <button 
            onClick={handleResetZoom}
            className="p-1.5 hover:bg-slate-800 rounded text-slate-300 hover:text-slate-100 transition-colors"
            title="Centralizar e Redefinir Vista"
          >
            <RotateCcw className="w-4 h-4" />
          </button>
        </div>

        {/* Floating Topology Legend (Bottom-Right) */}
        <div className="absolute bottom-4 right-4 hidden sm:flex items-center gap-3 px-3 py-1.5 bg-slate-950/80 backdrop-blur-md rounded-lg border border-slate-800/80 text-[11px] text-slate-400 font-mono shadow-md">
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 inline-block shadow-sm"></span>
            <span>Gateway</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-blue-500 inline-block"></span>
            <span>Switch / Infra</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-violet-500 inline-block"></span>
            <span>Kali SOC</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-500 inline-block"></span>
            <span>Servidor</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-rose-500 inline-block animate-ping"></span>
            <span className="text-rose-300">Rogue / Ameaça</span>
          </div>
        </div>

        {/* Hover Tooltip Overlay (when hovering a node) */}
        {hoveredNode && !selectedNode && (
          <div className="absolute top-4 left-4 z-20 p-3 bg-slate-950/95 backdrop-blur-md rounded-xl border border-slate-700 shadow-2xl max-w-xs space-y-1.5 pointer-events-none animate-fadeIn">
            <div className="flex items-center justify-between gap-2">
              <span className="text-xs font-bold text-slate-100 font-sans truncate">{hoveredNode.hostname}</span>
              <span className="text-[10px] font-mono font-bold px-1.5 py-0.2 rounded bg-slate-800 text-cyan-300 border border-slate-700">
                {hoveredNode.ip}
              </span>
            </div>
            <div className="text-[11px] text-slate-400 font-sans">
              Fabricante: <span className="text-slate-200">{hoveredNode.vendor}</span>
            </div>
            {hoveredNode.openPorts.length > 0 && (
              <div className="text-[10px] font-mono text-cyan-300 pt-1 border-t border-slate-800">
                Portas Nmap: {hoveredNode.openPorts.map(p => `${p.port}/${p.service}`).slice(0, 3).join(', ')}
                {hoveredNode.openPorts.length > 3 && ` (+${hoveredNode.openPorts.length - 3})`}
              </div>
            )}
            <div className="text-[10px] text-slate-500 italic">
              Clique para abrir detalhes e ações do Kali
            </div>
          </div>
        )}

        {/* 4. Slide-in Node Details & Nmap Audit Inspector (when node is clicked) */}
        {selectedNode && (
          <div className="absolute top-0 right-0 bottom-0 w-full sm:w-96 bg-slate-950/95 backdrop-blur-xl border-l border-slate-800 p-5 shadow-2xl z-30 flex flex-col justify-between overflow-y-auto animate-slideLeft">
            <div className="space-y-4">
              {/* Header */}
              <div className="flex items-start justify-between gap-2 border-b border-slate-800 pb-3">
                <div className="space-y-0.5">
                  <div className="flex items-center gap-2">
                    <h3 className="text-sm font-bold text-slate-100">{selectedNode.hostname}</h3>
                    {selectedNode.isRogue && (
                      <span className="text-[10px] font-mono font-bold bg-rose-950 text-rose-300 px-1.5 py-0.5 rounded border border-rose-800">
                        ROGUE
                      </span>
                    )}
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono text-cyan-400 font-semibold">{selectedNode.ip}</span>
                    <button
                      onClick={() => handleCopy(selectedNode.ip, 'sel-ip')}
                      className="text-slate-400 hover:text-slate-200"
                      title="Copiar IP"
                    >
                      {copiedKey === 'sel-ip' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    </button>
                  </div>
                </div>

                <button
                  onClick={() => setSelectedNode(null)}
                  className="p-1 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-slate-100 transition-colors"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>

              {/* Hardware & Identity Grid */}
              <div className="grid grid-cols-2 gap-2 text-xs">
                <div className="p-2.5 rounded-lg bg-slate-900/80 border border-slate-800/80">
                  <span className="text-[10px] uppercase font-semibold text-slate-400 block">Endereço MAC</span>
                  <span className="font-mono text-slate-200 text-[11px] truncate block">{selectedNode.mac}</span>
                </div>
                <div className="p-2.5 rounded-lg bg-slate-900/80 border border-slate-800/80">
                  <span className="text-[10px] uppercase font-semibold text-slate-400 block">Fabricante (OUI)</span>
                  <span className="text-slate-200 text-[11px] truncate block">{selectedNode.vendor}</span>
                </div>
                <div className="p-2.5 rounded-lg bg-slate-900/80 border border-slate-800/80">
                  <span className="text-[10px] uppercase font-semibold text-slate-400 block">Classificação</span>
                  <span className="text-slate-200 text-[11px] capitalize">{selectedNode.deviceType}</span>
                </div>
                <div className="p-2.5 rounded-lg bg-slate-900/80 border border-slate-800/80">
                  <span className="text-[10px] uppercase font-semibold text-slate-400 block">Confiabilidade</span>
                  <span className={`text-[11px] font-bold ${selectedNode.trustLevel === 'trusted' ? 'text-emerald-400' : selectedNode.trustLevel === 'blocked' ? 'text-rose-400' : 'text-amber-400'}`}>
                    {selectedNode.trustLevel.toUpperCase()}
                  </span>
                </div>
              </div>

              {/* Threat Score Bar */}
              <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 space-y-1.5">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-slate-400 font-medium">Índice de Risco / Ameaça</span>
                  <span className={`font-mono font-bold ${selectedNode.threatScore >= 60 ? 'text-rose-400' : selectedNode.threatScore >= 30 ? 'text-amber-400' : 'text-emerald-400'}`}>
                    {selectedNode.threatScore}/100
                  </span>
                </div>
                <div className="w-full bg-slate-950 h-2 rounded-full overflow-hidden border border-slate-800">
                  <div
                    className={`h-full transition-all duration-500 ${selectedNode.threatScore >= 60 ? 'bg-rose-500' : selectedNode.threatScore >= 30 ? 'bg-amber-500' : 'bg-emerald-500'}`}
                    style={{ width: `${Math.max(5, selectedNode.threatScore)}%` }}
                  />
                </div>
              </div>

              {/* Nmap Discovered Open Ports Table */}
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-slate-200 flex items-center gap-1.5">
                    <Activity className="w-3.5 h-3.5 text-cyan-400" />
                    <span>Portas Abertas Identificadas (Nmap)</span>
                  </span>
                  <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-900 text-slate-300 border border-slate-800 font-bold">
                    {selectedNode.openPorts.length}
                  </span>
                </div>

                {selectedNode.openPorts.length === 0 ? (
                  <div className="p-3 rounded-lg bg-slate-900/50 border border-slate-800 text-center text-xs text-slate-500">
                    Nenhuma porta de serviço aberta respondendo na varredura padrão.
                  </div>
                ) : (
                  <div className="space-y-1.5 max-h-48 overflow-y-auto pr-1">
                    {selectedNode.openPorts.map((p, idx) => (
                      <div 
                        key={idx}
                        className="p-2 rounded-lg bg-slate-900 border border-slate-800/80 flex items-center justify-between gap-2 text-xs hover:border-slate-700 transition-colors"
                      >
                        <div className="flex items-center gap-2 truncate">
                          <span className="font-mono font-bold text-cyan-400 shrink-0">:{p.port}</span>
                          <span className="text-slate-300 font-sans truncate">{p.service}</span>
                        </div>
                        <span className={`text-[9px] font-mono font-bold px-1.5 py-0.2 rounded border uppercase ${
                          p.risk === 'critical' ? 'bg-rose-950 text-rose-300 border-rose-800' :
                          p.risk === 'high' ? 'bg-amber-950 text-amber-300 border-amber-800' :
                          p.risk === 'medium' ? 'bg-yellow-950 text-yellow-300 border-yellow-800' :
                          'bg-slate-800 text-slate-300 border-slate-700'
                        }`}>
                          {p.risk}
                        </span>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Notes or details */}
              {selectedNode.notes && (
                <div className="p-2.5 rounded-lg bg-indigo-950/30 border border-indigo-900/50 text-xs text-indigo-200">
                  <span className="font-bold block mb-0.5">Nota de Auditoria:</span>
                  <span>{selectedNode.notes}</span>
                </div>
              )}
            </div>

            {/* Tactical Actions on Kali Linux */}
            <div className="pt-4 border-t border-slate-800 space-y-2 mt-4">
              <span className="text-[11px] uppercase font-semibold text-slate-400 block tracking-wider">
                Ações Táticas no Kali Linux
              </span>

              <div className="grid grid-cols-1 gap-2">
                {onOpenKaliTerminal && (
                  <button
                    onClick={() => onOpenKaliTerminal(`sudo nmap -sV -sC -O -Pn ${selectedNode.ip}`)}
                    className="flex items-center justify-center gap-1.5 px-3 py-2 bg-slate-900 hover:bg-slate-800 text-cyan-300 border border-slate-700 rounded-lg text-xs font-mono transition-colors"
                  >
                    <Terminal className="w-3.5 h-3.5" />
                    <span>Nmap Deep Scan ({selectedNode.ip})</span>
                  </button>
                )}

                {onOpenAIForensic && (
                  <button
                    onClick={() => onOpenAIForensic('device', selectedNode as any)}
                    className="flex items-center justify-center gap-1.5 px-3 py-2 bg-indigo-950 hover:bg-indigo-900 text-indigo-300 border border-indigo-800 rounded-lg text-xs font-semibold transition-colors"
                  >
                    <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
                    <span>Auditoria Forense com IA</span>
                  </button>
                )}

                {onOpenKaliTerminal && (
                  <button
                    onClick={() => onOpenKaliTerminal(`sudo iptables -I INPUT -s ${selectedNode.ip} -j DROP && sudo iptables -I FORWARD -s ${selectedNode.ip} -j DROP`)}
                    className="flex items-center justify-center gap-1.5 px-3 py-2 bg-rose-950 hover:bg-rose-900 text-rose-300 border border-rose-800 rounded-lg text-xs font-mono transition-colors"
                  >
                    <ShieldAlert className="w-3.5 h-3.5" />
                    <span>Bloquear Host no Iptables</span>
                  </button>
                )}
              </div>
            </div>
          </div>
        )}
      </div>

      {/* 5. Footer Summary Bar */}
      <div className="px-4 py-2 bg-slate-950 border-t border-slate-800 flex flex-wrap items-center justify-between text-xs text-slate-400 gap-2 shrink-0">
        <div className="flex items-center gap-3">
          <span>Nós Ativos: <strong className="text-slate-200">{filteredNodes.length}</strong></span>
          <span className="text-slate-600">·</span>
          <span>Enlaces: <strong className="text-slate-200">{filteredLinks.length}</strong></span>
          <span className="text-slate-600">·</span>
          <span>Portas Auditadas: <strong className="text-cyan-400">{totalOpenPorts}</strong></span>
        </div>

        <div className="text-[11px] text-slate-500 flex items-center gap-1">
          <Info className="w-3.5 h-3.5" />
          <span>Arraste os nós para reorganizar · Role com o mouse para zoom · Clique para inspecionar</span>
        </div>
      </div>
    </div>
  );
};
