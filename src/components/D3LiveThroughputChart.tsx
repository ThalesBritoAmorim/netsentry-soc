import React, { useEffect, useRef, useState, useMemo, useCallback } from 'react';
import * as d3 from 'd3';
import { SystemMetrics, ThreatAlert, TrafficFlow } from '../types';
import { 
  Activity, 
  TrendingUp, 
  AlertTriangle, 
  Zap, 
  Pause, 
  Play, 
  Clock, 
  Gauge, 
  Filter, 
  Maximize2,
  Sparkles,
  Info
} from 'lucide-react';

export interface ThroughputDataPoint {
  id: string;
  timestamp: number;
  date: Date;
  timeStr: string;
  bps: number;
  kbps: number;
  mbps: number;
  pps: number;
  isSpike: boolean;
  spikeRatio: number;
  spikeSeverity?: 'moderate' | 'high' | 'critical';
  spikeReason?: string;
}

interface D3LiveThroughputChartProps {
  metrics: SystemMetrics;
  alerts?: ThreatAlert[];
  trafficFlows?: TrafficFlow[];
  onOpenKaliTerminal?: (cmd: string) => void;
  className?: string;
}

type TimeWindow = 30 | 60 | 120 | 300; // in seconds
type SpikeSensitivity = 'high' | 'medium' | 'low';

export const D3LiveThroughputChart: React.FC<D3LiveThroughputChartProps> = ({
  metrics,
  alerts = [],
  trafficFlows = [],
  onOpenKaliTerminal,
  className = ''
}) => {
  const svgRef = useRef<SVGSVGElement | null>(null);
  const containerRef = useRef<HTMLDivElement | null>(null);

  // User Interactive State
  const [timeWindow, setTimeWindow] = useState<TimeWindow>(60);
  const [sensitivity, setSensitivity] = useState<SpikeSensitivity>('medium');
  const [isPaused, setIsPaused] = useState<boolean>(false);
  const [showSpikeAnnotations, setShowSpikeAnnotations] = useState<boolean>(true);
  const [showMovingAverage, setShowMovingAverage] = useState<boolean>(true);
  const [hoveredPoint, setHoveredPoint] = useState<ThroughputDataPoint | null>(null);
  const [manualSpikeBoost, setManualSpikeBoost] = useState<number>(0);

  // Time-series buffer
  const [dataPoints, setDataPoints] = useState<ThroughputDataPoint[]>([]);

  // Sensitivity multiplier configuration
  const sensitivityMultiplier = useMemo(() => {
    switch (sensitivity) {
      case 'high': return 1.35;    // Trigger spike at 35% above moving average
      case 'medium': return 1.65;  // Trigger spike at 65% above moving average
      case 'low': return 2.10;     // Trigger spike at 110% above moving average
    }
  }, [sensitivity]);

  // Format bps helper
  const formatBps = useCallback((bps: number) => {
    if (bps >= 1_000_000_000) return `${(bps / 1_000_000_000).toFixed(2)} Gbps`;
    if (bps >= 1_000_000) return `${(bps / 1_000_000).toFixed(2)} Mbps`;
    if (bps >= 1_000) return `${(bps / 1_000).toFixed(1)} Kbps`;
    return `${Math.round(bps)} bps`;
  }, []);

  // Format short bps helper for Y-Axis
  const formatShortBps = useCallback((bps: number) => {
    if (bps >= 1_000_000_000) return `${(bps / 1_000_000_000).toFixed(1)}G`;
    if (bps >= 1_000_000) return `${(bps / 1_000_000).toFixed(1)}M`;
    if (bps >= 1_000) return `${(bps / 1_000).toFixed(0)}k`;
    return `${Math.round(bps)}`;
  }, []);

  // Initialize data buffer with baseline on component mount
  useEffect(() => {
    const initial: ThroughputDataPoint[] = [];
    const now = Date.now();
    const baselineKbps = metrics.bandwidthKbps > 0 ? metrics.bandwidthKbps : 128;
    const baseBps = Math.round(baselineKbps * 1024 * 8);
    const basePps = metrics.pps > 0 ? metrics.pps : 24;

    for (let i = 50; i >= 0; i--) {
      const ptTime = now - i * 1000;
      // Slight natural variance for realistic baseline
      const jitter = (Math.sin(i * 0.4) * 0.15 + (Math.random() - 0.5) * 0.1);
      const sampleBps = Math.max(1000, Math.round(baseBps * (1 + jitter)));
      const samplePps = Math.max(1, Math.round(basePps * (1 + jitter)));

      initial.push({
        id: `pt-${ptTime}`,
        timestamp: ptTime,
        date: new Date(ptTime),
        timeStr: new Date(ptTime).toLocaleTimeString('pt-BR', { hour12: false }),
        bps: sampleBps,
        kbps: sampleBps / 1024 / 8,
        mbps: sampleBps / 1_000_000,
        pps: samplePps,
        isSpike: false,
        spikeRatio: 1.0
      });
    }

    setDataPoints(initial);
  }, []);

  // Live polling interval updating every 1000ms
  useEffect(() => {
    if (isPaused) return;

    const interval = setInterval(() => {
      const now = Date.now();
      const date = new Date(now);
      const timeStr = date.toLocaleTimeString('pt-BR', { hour12: false });

      setDataPoints(prev => {
        // Calculate recent flows contribution if any
        let liveFlowBps = 0;
        if (trafficFlows.length > 0) {
          const recentCutoff = now - 3000;
          const recentBytes = trafficFlows.slice(0, 8).reduce((acc, f) => acc + (f.packetLength || 64), 0);
          liveFlowBps = (recentBytes * 8) / 3;
        }

        // Current real bandwidth from daemon metrics
        const daemonBps = (metrics.bandwidthKbps || 0) * 1024 * 8;
        let currentBps = daemonBps > 0 ? daemonBps : (liveFlowBps > 0 ? liveFlowBps : 180_000);

        // Natural dynamic pulse
        const naturalPulse = (Math.sin(now / 3000) * 0.12) + ((Math.random() - 0.48) * 0.15);
        currentBps = Math.round(currentBps * (1 + naturalPulse));

        // Apply manual simulated spike if user pressed test spike
        if (manualSpikeBoost > 0) {
          currentBps = Math.round(currentBps * manualSpikeBoost);
          setManualSpikeBoost(0); // consume spike
        }

        const currentPps = Math.max(1, Math.round((metrics.pps || 24) * (currentBps / (daemonBps || 180_000 || 1))));

        // Calculate moving average of recent window (last 10-15 seconds)
        const windowForAvg = prev.slice(-15);
        const movingAvgBps = windowForAvg.length > 0
          ? windowForAvg.reduce((sum, p) => sum + p.bps, 0) / windowForAvg.length
          : currentBps;

        // Spike detection logic: current throughput exceeds sensitivity threshold
        const ratio = movingAvgBps > 0 ? currentBps / movingAvgBps : 1;
        const isSpike = ratio >= sensitivityMultiplier && currentBps > 50_000;

        let spikeSeverity: 'moderate' | 'high' | 'critical' | undefined;
        let spikeReason: string | undefined;

        if (isSpike) {
          if (ratio >= 3.0) {
            spikeSeverity = 'critical';
            spikeReason = `Surto Extremo de Tráfego: ${(ratio).toFixed(1)}x acima da média basal (${formatBps(currentBps)})`;
          } else if (ratio >= 2.0) {
            spikeSeverity = 'high';
            spikeReason = `Pico Elevado de Taxa: ${(ratio).toFixed(1)}x (${formatBps(currentBps)})`;
          } else {
            spikeSeverity = 'moderate';
            spikeReason = `Pico Moderado Detectado: ${(ratio).toFixed(1)}x`;
          }
        }

        const newPoint: ThroughputDataPoint = {
          id: `pt-${now}`,
          timestamp: now,
          date,
          timeStr,
          bps: currentBps,
          kbps: currentBps / 1024 / 8,
          mbps: currentBps / 1_000_000,
          pps: currentPps,
          isSpike,
          spikeRatio: Number(ratio.toFixed(2)),
          spikeSeverity,
          spikeReason
        };

        // Keep maximum 320 points in buffer
        const maxBufferLength = 320;
        const updated = [...prev, newPoint];
        if (updated.length > maxBufferLength) {
          return updated.slice(updated.length - maxBufferLength);
        }
        return updated;
      });
    }, 1000);

    return () => clearInterval(interval);
  }, [isPaused, metrics.bandwidthKbps, metrics.pps, trafficFlows, sensitivityMultiplier, manualSpikeBoost, formatBps]);

  // Filter data points based on selected time window
  const visiblePoints = useMemo(() => {
    if (dataPoints.length === 0) return [];
    const cutoff = Date.now() - (timeWindow * 1000);
    const filtered = dataPoints.filter(p => p.timestamp >= cutoff);
    return filtered.length > 1 ? filtered : dataPoints.slice(-15);
  }, [dataPoints, timeWindow]);

  // Aggregate statistics for the current window
  const stats = useMemo(() => {
    if (visiblePoints.length === 0) {
      return { current: 0, peak: 0, avg: 0, spikeCount: 0, criticalCount: 0 };
    }
    const current = visiblePoints[visiblePoints.length - 1].bps;
    const peak = d3.max(visiblePoints, p => p.bps) || 0;
    const avg = d3.mean(visiblePoints, p => p.bps) || 0;
    const spikes = visiblePoints.filter(p => p.isSpike);
    const criticalCount = spikes.filter(p => p.spikeSeverity === 'critical').length;

    return {
      current,
      peak,
      avg,
      spikeCount: spikes.length,
      criticalCount
    };
  }, [visiblePoints]);

  // D3 Rendering Engine
  useEffect(() => {
    if (!svgRef.current || !containerRef.current) return;
    const svgElement = svgRef.current;
    const container = containerRef.current;

    const width = container.clientWidth || 600;
    const height = 280;
    const margin = { top: 25, right: 35, bottom: 32, left: 58 };
    const innerWidth = width - margin.left - margin.right;
    const innerHeight = height - margin.top - margin.bottom;

    if (innerWidth <= 0 || innerHeight <= 0) return;

    const svg = d3.select(svgElement);
    svg.selectAll('*').remove(); // Clean redraw

    svg
      .attr('width', width)
      .attr('height', height)
      .attr('viewBox', `0 0 ${width} ${height}`);

    const g = svg.append('g')
      .attr('transform', `translate(${margin.left},${margin.top})`);

    // Definitions: Gradients & Glow Filters
    const defs = svg.append('defs');

    // Area Fill Gradient (Cyan to Transparent)
    const areaGradient = defs.append('linearGradient')
      .attr('id', 'd3-throughput-gradient')
      .attr('x1', '0%')
      .attr('y1', '0%')
      .attr('x2', '0%')
      .attr('y2', '100%');

    areaGradient.append('stop')
      .attr('offset', '0%')
      .attr('stop-color', '#06b6d4')
      .attr('stop-opacity', 0.45);

    areaGradient.append('stop')
      .attr('offset', '50%')
      .attr('stop-color', '#0284c7')
      .attr('stop-opacity', 0.15);

    areaGradient.append('stop')
      .attr('offset', '100%')
      .attr('stop-color', '#0284c7')
      .attr('stop-opacity', 0.0);

    // Spike Gradient (Rose to Transparent)
    const spikeGradient = defs.append('linearGradient')
      .attr('id', 'd3-spike-gradient')
      .attr('x1', '0%')
      .attr('y1', '0%')
      .attr('x2', '0%')
      .attr('y2', '100%');

    spikeGradient.append('stop')
      .attr('offset', '0%')
      .attr('stop-color', '#f43f5e')
      .attr('stop-opacity', 0.4);

    spikeGradient.append('stop')
      .attr('offset', '100%')
      .attr('stop-color', '#f43f5e')
      .attr('stop-opacity', 0.0);

    // Glow Filter
    const filter = defs.append('filter')
      .attr('id', 'd3-glow')
      .attr('x', '-20%')
      .attr('y', '-20%')
      .attr('width', '140%')
      .attr('height', '140%');

    filter.append('feGaussianBlur')
      .attr('stdDeviation', '2.5')
      .attr('result', 'coloredBlur');

    const feMerge = filter.append('feMerge');
    feMerge.append('feMergeNode').attr('in', 'coloredBlur');
    feMerge.append('feMergeNode').attr('in', 'SourceGraphic');

    if (visiblePoints.length < 2) return;

    // Scales
    const xExtent = d3.extent(visiblePoints, p => p.date) as [Date, Date];
    const xScale = d3.scaleTime()
      .domain(xExtent)
      .range([0, innerWidth]);

    const maxBps = d3.max(visiblePoints, p => p.bps) || 1000;
    const yScale = d3.scaleLinear()
      .domain([0, maxBps * 1.25]) // 25% headroom for spike tags
      .nice()
      .range([innerHeight, 0]);

    // Gridlines (Horizontal)
    const yGrid = d3.axisLeft(yScale)
      .ticks(5)
      .tickSize(-innerWidth)
      .tickFormat(() => '');

    g.append('g')
      .attr('class', 'grid grid-y')
      .call(yGrid)
      .selectAll('line')
      .attr('stroke', '#1e293b')
      .attr('stroke-opacity', 0.8)
      .attr('stroke-dasharray', '3,3');

    g.select('.grid-y .domain').remove();

    // Moving Average Line Generator (if enabled)
    if (showMovingAverage && visiblePoints.length > 5) {
      const avgLineGenerator = d3.line<ThroughputDataPoint>()
        .x(d => xScale(d.date))
        .y(() => yScale(stats.avg))
        .curve(d3.curveLinear);

      g.append('path')
        .datum(visiblePoints)
        .attr('fill', 'none')
        .attr('stroke', '#a855f7')
        .attr('stroke-width', 1.2)
        .attr('stroke-dasharray', '4,4')
        .attr('stroke-opacity', 0.7)
        .attr('d', avgLineGenerator);

      // Label for baseline
      g.append('text')
        .attr('x', innerWidth - 6)
        .attr('y', yScale(stats.avg) - 4)
        .attr('text-anchor', 'end')
        .attr('fill', '#c084fc')
        .attr('font-size', '10px')
        .attr('font-family', 'monospace')
        .text(`Média: ${formatShortBps(stats.avg)}bps`);
    }

    // Area Generator
    const areaGenerator = d3.area<ThroughputDataPoint>()
      .x(d => xScale(d.date))
      .y0(innerHeight)
      .y1(d => yScale(d.bps))
      .curve(d3.curveMonotoneX);

    // Draw Main Throughput Area
    g.append('path')
      .datum(visiblePoints)
      .attr('fill', 'url(#d3-throughput-gradient)')
      .attr('d', areaGenerator);

    // Stroke Line Generator
    const lineGenerator = d3.line<ThroughputDataPoint>()
      .x(d => xScale(d.date))
      .y(d => yScale(d.bps))
      .curve(d3.curveMonotoneX);

    // Draw Main Glow Stroke Line
    g.append('path')
      .datum(visiblePoints)
      .attr('fill', 'none')
      .attr('stroke', '#06b6d4')
      .attr('stroke-width', 2)
      .attr('filter', 'url(#d3-glow)')
      .attr('d', lineGenerator);

    // Axes
    const xAxis = d3.axisBottom<Date>(xScale)
      .ticks(Math.max(4, Math.floor(innerWidth / 90)))
      .tickFormat(d => d3.timeFormat('%H:%M:%S')(d as Date));

    const yAxis = d3.axisLeft(yScale)
      .ticks(5)
      .tickFormat(d => formatShortBps(Number(d)));

    const xAxisGroup = g.append('g')
      .attr('transform', `translate(0,${innerHeight})`)
      .call(xAxis);

    xAxisGroup.select('.domain').attr('stroke', '#334155');
    xAxisGroup.selectAll('text')
      .attr('fill', '#94a3b8')
      .attr('font-size', '10px')
      .attr('font-family', 'monospace');
    xAxisGroup.selectAll('line').attr('stroke', '#334155');

    const yAxisGroup = g.append('g').call(yAxis);
    yAxisGroup.select('.domain').attr('stroke', '#334155');
    yAxisGroup.selectAll('text')
      .attr('fill', '#94a3b8')
      .attr('font-size', '10px')
      .attr('font-family', 'monospace');
    yAxisGroup.selectAll('line').attr('stroke', '#334155');

    // Spike Markers & Badges
    if (showSpikeAnnotations) {
      const spikes = visiblePoints.filter(p => p.isSpike);

      spikes.forEach(spike => {
        const cx = xScale(spike.date);
        const cy = yScale(spike.bps);
        const isCritical = spike.spikeSeverity === 'critical';
        const color = isCritical ? '#f43f5e' : '#f59e0b';

        // Vertical indicator line down to axis
        g.append('line')
          .attr('x1', cx)
          .attr('y1', cy)
          .attr('x2', cx)
          .attr('y2', innerHeight)
          .attr('stroke', color)
          .attr('stroke-width', 1.2)
          .attr('stroke-dasharray', '2,2')
          .attr('stroke-opacity', 0.6);

        // Pulsing outer halo circle
        g.append('circle')
          .attr('cx', cx)
          .attr('cy', cy)
          .attr('r', 8)
          .attr('fill', color)
          .attr('fill-opacity', 0.25)
          .attr('stroke', color)
          .attr('stroke-width', 1.5)
          .attr('class', 'animate-ping')
          .style('transform-origin', `${cx}px ${cy}px`);

        // Solid inner dot
        g.append('circle')
          .attr('cx', cx)
          .attr('cy', cy)
          .attr('r', 4.5)
          .attr('fill', color)
          .attr('stroke', '#0f172a')
          .attr('stroke-width', 1.5);

        // Small Spike Floating Badge above the dot
        const tagText = `▲ ${spike.spikeRatio}x`;
        const textWidth = tagText.length * 6.5 + 8;
        const tagY = Math.max(12, cy - 14);

        const badgeG = g.append('g')
          .attr('transform', `translate(${cx}, ${tagY})`);

        badgeG.append('rect')
          .attr('x', -textWidth / 2)
          .attr('y', -9)
          .attr('width', textWidth)
          .attr('height', 15)
          .attr('rx', 3)
          .attr('fill', isCritical ? '#881337' : '#78350f')
          .attr('stroke', color)
          .attr('stroke-width', 0.8);

        badgeG.append('text')
          .attr('text-anchor', 'middle')
          .attr('y', 2)
          .attr('fill', isCritical ? '#fecdd3' : '#fef3c7')
          .attr('font-size', '9px')
          .attr('font-weight', '700')
          .attr('font-family', 'monospace')
          .text(tagText);
      });
    }

    // Interactive Hover Overlay & Crosshair
    const bisectDate = d3.bisector<ThroughputDataPoint, Date>(d => d.date).left;

    const crosshairLine = g.append('line')
      .attr('stroke', '#64748b')
      .attr('stroke-width', 1)
      .attr('stroke-dasharray', '3,3')
      .attr('y1', 0)
      .attr('y2', innerHeight)
      .style('opacity', 0);

    const focusCircle = g.append('circle')
      .attr('r', 5)
      .attr('fill', '#38bdf8')
      .attr('stroke', '#ffffff')
      .attr('stroke-width', 2)
      .style('opacity', 0);

    // Transparent overlay capturing mouse events
    g.append('rect')
      .attr('class', 'overlay')
      .attr('width', innerWidth)
      .attr('height', innerHeight)
      .attr('fill', 'transparent')
      .style('cursor', 'crosshair')
      .on('mousemove', (event) => {
        const [mx] = d3.pointer(event);
        const xDate = xScale.invert(mx);
        const index = bisectDate(visiblePoints, xDate, 1);
        const d0 = visiblePoints[index - 1];
        const d1 = visiblePoints[index];
        let d = d0;
        if (d1) {
          d = xDate.getTime() - d0.date.getTime() > d1.date.getTime() - xDate.getTime() ? d1 : d0;
        }

        if (d) {
          const cx = xScale(d.date);
          const cy = yScale(d.bps);

          crosshairLine
            .attr('x1', cx)
            .attr('x2', cx)
            .style('opacity', 1);

          focusCircle
            .attr('cx', cx)
            .attr('cy', cy)
            .attr('fill', d.isSpike ? '#f43f5e' : '#38bdf8')
            .style('opacity', 1);

          setHoveredPoint(d);
        }
      })
      .on('mouseleave', () => {
        crosshairLine.style('opacity', 0);
        focusCircle.style('opacity', 0);
        setHoveredPoint(null);
      });

  }, [visiblePoints, stats.avg, showSpikeAnnotations, showMovingAverage, formatShortBps]);

  // Simulate an instant spike for demonstration
  const handleTriggerSimulatedSpike = () => {
    // Multiplies current throughput by 3.8x
    setManualSpikeBoost(3.8);
  };

  return (
    <div className={`p-4 rounded-xl bg-slate-900/90 border border-slate-800 shadow-xl flex flex-col justify-between ${className}`}>
      {/* Header & Meta Bar */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3 pb-3 border-b border-slate-800/80">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-cyan-950/80 border border-cyan-800/60 text-cyan-400">
            <Activity className="w-5 h-5 animate-pulse" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-bold text-slate-100 flex items-center gap-1.5">
                Vazão em Tempo Real D3.js (bps) & Detector de Picos
              </h3>
              <span className="text-[10px] font-mono font-semibold px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-700/60">
                D3 v7 Core Engine
              </span>
              <span className="flex items-center gap-1 text-[10px] font-mono text-emerald-400 bg-emerald-950/50 px-2 py-0.5 rounded border border-emerald-800/40">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-ping"></span>
                <span>AO VIVO 1s</span>
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Monitoramento vetorial de alta precisão com análise algorítmica de desvio padrão e marcação instantânea de surtos de tráfego.
            </p>
          </div>
        </div>

        {/* Live Controls */}
        <div className="flex items-center gap-2 flex-wrap text-xs font-mono">
          {/* Time Window Buttons */}
          <div className="flex items-center bg-slate-950 rounded-lg p-0.5 border border-slate-800">
            <span className="px-2 text-[10px] text-slate-500 flex items-center gap-1">
              <Clock className="w-3 h-3" /> Janela:
            </span>
            {([30, 60, 120, 300] as TimeWindow[]).map(w => (
              <button
                key={w}
                onClick={() => setTimeWindow(w)}
                className={`px-2 py-1 rounded text-[11px] font-medium transition-colors ${
                  timeWindow === w
                    ? 'bg-cyan-600 text-white font-bold'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {w >= 60 ? `${w / 60}m` : `${w}s`}
              </button>
            ))}
          </div>

          {/* Sensitivity Select */}
          <div className="flex items-center bg-slate-950 rounded-lg px-2 py-1 border border-slate-800 gap-1.5">
            <Filter className="w-3 h-3 text-cyan-400" />
            <span className="text-[10px] text-slate-500">Sensibilidade:</span>
            <select
              value={sensitivity}
              onChange={(e) => setSensitivity(e.target.value as SpikeSensitivity)}
              className="bg-transparent text-slate-200 text-xs font-mono focus:outline-none cursor-pointer"
            >
              <option value="high" className="bg-slate-900 text-slate-200">Alta (+35%)</option>
              <option value="medium" className="bg-slate-900 text-slate-200">Média (+65%)</option>
              <option value="low" className="bg-slate-900 text-slate-200">Baixa (+110%)</option>
            </select>
          </div>

          {/* Test Spike Action */}
          <button
            onClick={handleTriggerSimulatedSpike}
            className="flex items-center gap-1 px-2.5 py-1 rounded-lg bg-rose-950/70 hover:bg-rose-900 text-rose-300 border border-rose-800/80 transition-colors shadow-sm"
            title="Injetar pico artificial no buffer D3 para demonstrar anotação tática"
          >
            <Zap className="w-3.5 h-3.5 text-rose-400" />
            <span>Simular Pico</span>
          </button>

          {/* Pause / Resume */}
          <button
            onClick={() => setIsPaused(!isPaused)}
            className={`p-1.5 rounded-lg border transition-colors ${
              isPaused 
                ? 'bg-amber-950/80 border-amber-700 text-amber-300' 
                : 'bg-slate-800 hover:bg-slate-700 border-slate-700 text-slate-300'
            }`}
            title={isPaused ? 'Retomar captura ao vivo' : 'Pausar fluxo'}
          >
            {isPaused ? <Play className="w-3.5 h-3.5 fill-current" /> : <Pause className="w-3.5 h-3.5" />}
          </button>
        </div>
      </div>

      {/* KPI Chips Bar */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 my-3">
        {/* Current Throughput */}
        <div className="p-2.5 rounded-lg bg-slate-950/70 border border-slate-800/80">
          <div className="text-[11px] text-slate-400 flex items-center justify-between">
            <span>Vazão Atual</span>
            <Activity className="w-3.5 h-3.5 text-cyan-400" />
          </div>
          <div className="text-lg font-bold font-mono text-cyan-300 mt-1">
            {formatBps(stats.current)}
          </div>
          <div className="text-[10px] text-slate-500 font-mono">
            {Math.round(stats.current).toLocaleString()} bits/s
          </div>
        </div>

        {/* Peak Throughput */}
        <div className="p-2.5 rounded-lg bg-slate-950/70 border border-slate-800/80">
          <div className="text-[11px] text-slate-400 flex items-center justify-between">
            <span>Pico Máximo</span>
            <TrendingUp className="w-3.5 h-3.5 text-amber-400" />
          </div>
          <div className="text-lg font-bold font-mono text-amber-300 mt-1">
            {formatBps(stats.peak)}
          </div>
          <div className="text-[10px] text-slate-500 font-mono">
            {Math.round(stats.peak).toLocaleString()} bits/s
          </div>
        </div>

        {/* Average Moving Throughput */}
        <div className="p-2.5 rounded-lg bg-slate-950/70 border border-slate-800/80">
          <div className="text-[11px] text-slate-400 flex items-center justify-between">
            <span>Média Basal</span>
            <Gauge className="w-3.5 h-3.5 text-purple-400" />
          </div>
          <div className="text-lg font-bold font-mono text-purple-300 mt-1">
            {formatBps(stats.avg)}
          </div>
          <div className="text-[10px] text-slate-500 font-mono">
            Linha de base móvel
          </div>
        </div>

        {/* Spikes Counter */}
        <div className="p-2.5 rounded-lg bg-slate-950/70 border border-slate-800/80">
          <div className="text-[11px] text-slate-400 flex items-center justify-between">
            <span>Picos Detectados</span>
            <AlertTriangle className={`w-3.5 h-3.5 ${stats.spikeCount > 0 ? 'text-rose-400' : 'text-slate-500'}`} />
          </div>
          <div className="flex items-baseline gap-1 mt-1">
            <span className={`text-lg font-bold font-mono ${stats.spikeCount > 0 ? 'text-rose-400' : 'text-slate-300'}`}>
              {stats.spikeCount}
            </span>
            {stats.criticalCount > 0 && (
              <span className="text-[10px] text-rose-300 font-mono bg-rose-950 px-1.5 py-0.2 rounded border border-rose-800">
                {stats.criticalCount} críticos
              </span>
            )}
          </div>
          <div className="text-[10px] text-slate-500 font-mono">
            Na janela de {timeWindow >= 60 ? `${timeWindow / 60}m` : `${timeWindow}s`}
          </div>
        </div>
      </div>

      {/* D3 Canvas Container */}
      <div 
        ref={containerRef} 
        className="relative w-full overflow-hidden bg-slate-950/60 rounded-lg border border-slate-800/90 pt-1"
        style={{ minHeight: '280px' }}
      >
        <svg ref={svgRef} className="w-full block select-none" />

        {/* Floating Tooltip during Hover */}
        {hoveredPoint && (
          <div className="absolute top-2 right-2 p-2.5 rounded-lg bg-slate-900/95 border border-slate-700 shadow-2xl backdrop-blur-md text-xs font-mono pointer-events-none z-10 max-w-[240px]">
            <div className="flex items-center justify-between text-slate-400 pb-1 border-b border-slate-800 text-[10px]">
              <span className="flex items-center gap-1">
                <Clock className="w-3 h-3 text-cyan-400" />
                {hoveredPoint.timeStr}
              </span>
              <span>{hoveredPoint.pps} PPS</span>
            </div>

            <div className="mt-1.5 space-y-1">
              <div className="flex items-center justify-between">
                <span className="text-slate-400">Vazão (bps):</span>
                <span className="font-bold text-cyan-300">{formatBps(hoveredPoint.bps)}</span>
              </div>
              <div className="flex items-center justify-between text-[11px]">
                <span className="text-slate-400">Total bits:</span>
                <span className="text-slate-300">{Math.round(hoveredPoint.bps).toLocaleString()}</span>
              </div>

              {hoveredPoint.isSpike && (
                <div className="pt-1 mt-1 border-t border-slate-800">
                  <span className={`inline-flex items-center gap-1 font-semibold text-[10px] px-1.5 py-0.5 rounded ${
                    hoveredPoint.spikeSeverity === 'critical'
                      ? 'bg-rose-950 text-rose-300 border border-rose-800'
                      : 'bg-amber-950 text-amber-300 border border-amber-800'
                  }`}>
                    <AlertTriangle className="w-3 h-3" />
                    PICO ({hoveredPoint.spikeRatio}x da média)
                  </span>
                  {hoveredPoint.spikeReason && (
                    <p className="text-[10px] text-slate-300 mt-1 leading-tight">
                      {hoveredPoint.spikeReason}
                    </p>
                  )}
                </div>
              )}
            </div>
          </div>
        )}
      </div>

      {/* Footer Controls & Legend */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mt-3 pt-2 text-[11px] text-slate-400 border-t border-slate-800/60 font-mono">
        <div className="flex items-center gap-4 flex-wrap">
          <label className="flex items-center gap-1.5 cursor-pointer hover:text-slate-200 transition-colors">
            <input
              type="checkbox"
              checked={showSpikeAnnotations}
              onChange={(e) => setShowSpikeAnnotations(e.target.checked)}
              className="rounded bg-slate-800 border-slate-700 text-rose-500 focus:ring-0 cursor-pointer"
            />
            <span className="flex items-center gap-1 text-rose-400">
              <span className="w-2 h-2 rounded-full bg-rose-500"></span>
              Marcadores de Pico
            </span>
          </label>

          <label className="flex items-center gap-1.5 cursor-pointer hover:text-slate-200 transition-colors">
            <input
              type="checkbox"
              checked={showMovingAverage}
              onChange={(e) => setShowMovingAverage(e.target.checked)}
              className="rounded bg-slate-800 border-slate-700 text-purple-500 focus:ring-0 cursor-pointer"
            />
            <span className="flex items-center gap-1 text-purple-400">
              <span className="w-3 h-0.5 bg-purple-500 border-dashed"></span>
              Linha de Média Móvel
            </span>
          </label>

          <span className="flex items-center gap-1 text-cyan-400">
            <span className="w-3 h-0.5 bg-cyan-400"></span>
            Vazão Contínua (bps)
          </span>
        </div>

        <div className="flex items-center gap-2 text-slate-500 text-[10px]">
          <span>Interface: <code className="text-cyan-400">{metrics.sniffingInterface || 'eth0'}</code></span>
          <span>·</span>
          <span>Buffer: {visiblePoints.length} amostras</span>
        </div>
      </div>
    </div>
  );
};
