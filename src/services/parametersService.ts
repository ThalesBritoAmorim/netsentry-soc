import { AnalysisParameters } from '../types';

export const DEFAULT_ANALYSIS_PARAMETERS: AnalysisParameters = {
  // Detection Thresholds
  ppsFloodThreshold: 600,
  portScanThreshold: 15,
  dnsEntropyThreshold: 4.2,
  arpSpoofSensitivity: 'strict',

  // Network Filters & Whitelists
  whitelistedIps: ['192.168.0.156', '192.168.0.1', '192.168.1.1', '127.0.0.1', '1.1.1.1', '8.8.8.8'],
  protectedPorts: [22, 80, 443, 3000, 5432, 8080],
  monitoredSubnets: ['192.168.0.0/24', '192.168.1.0/24'],

  // AI Forensic Parameters
  forensicDetailLevel: 'deep_forensic',
  prioritizeMitre: true,
  iptablesRuleType: 'drop',
  autoAnonymizeTopology: true,

  // Response & Mitigation Policies
  autoBlockHighSeverity: true,
  blockTtlMinutes: 60,
  enableAudioAlerts: false,
  enableDesktopBanners: true,
};

const STORAGE_KEY = 'netsentry_analysis_parameters_v1';

class ParametersService {
  private params: AnalysisParameters;

  constructor() {
    this.params = this.load();
    // Guarantee Kali host IP is always present in whitelist
    if (!this.params.whitelistedIps.includes('192.168.0.156')) {
      this.params.whitelistedIps.push('192.168.0.156');
    }
  }

  public get(): AnalysisParameters {
    return { ...this.params };
  }

  public addWhitelistedIp(ip: string): boolean {
    const cleanIp = ip.trim();
    if (!cleanIp || this.params.whitelistedIps.includes(cleanIp)) return false;
    this.save({ whitelistedIps: [...this.params.whitelistedIps, cleanIp] });
    return true;
  }

  public isWhitelisted(ip: string): boolean {
    if (!ip) return false;
    const cleanIp = ip.trim();
    return (
      cleanIp === '127.0.0.1' ||
      cleanIp === 'localhost' ||
      cleanIp === '192.168.0.156' ||
      this.params.whitelistedIps.includes(cleanIp)
    );
  }

  public save(newParams: Partial<AnalysisParameters>): AnalysisParameters {
    this.params = { ...this.params, ...newParams };
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(this.params));
    } catch (e) {
      console.warn('Erro ao salvar parâmetros no localStorage:', e);
    }
    return { ...this.params };
  }

  public reset(): AnalysisParameters {
    this.params = { ...DEFAULT_ANALYSIS_PARAMETERS };
    try {
      localStorage.removeItem(STORAGE_KEY);
    } catch (e) {}
    return { ...this.params };
  }

  private load(): AnalysisParameters {
    try {
      const saved = localStorage.getItem(STORAGE_KEY);
      if (saved) {
        return { ...DEFAULT_ANALYSIS_PARAMETERS, ...JSON.parse(saved) };
      }
    } catch (e) {}
    return { ...DEFAULT_ANALYSIS_PARAMETERS };
  }
}

export const parametersService = new ParametersService();
