import { parametersService } from './parametersService';

export type SoundEffectType = 'critical' | 'warning' | 'success' | 'spike';

class SoundAlertService {
  private audioCtx: AudioContext | null = null;
  private isUserMuted: boolean = false;
  private listeners: Set<(muted: boolean) => void> = new Set();
  private lastPlayedTime: number = 0;
  private readonly MIN_COOLDOWN_MS = 1200; // Prevent ear fatigue / sound overlapping

  constructor() {
    // Check initial mute state from parameters
    const params = parametersService.get();
    this.isUserMuted = !params.enableAudioAlerts;
  }

  private getAudioContext(): AudioContext | null {
    if (typeof window === 'undefined') return null;

    if (!this.audioCtx) {
      const AudioCtxClass = window.AudioContext || (window as any).webkitAudioContext;
      if (AudioCtxClass) {
        this.audioCtx = new AudioCtxClass();
      }
    }

    if (this.audioCtx && this.audioCtx.state === 'suspended') {
      this.audioCtx.resume().catch(() => {});
    }

    return this.audioCtx;
  }

  public isMuted(): boolean {
    const params = parametersService.get();
    return !params.enableAudioAlerts || this.isUserMuted;
  }

  public setMuted(muted: boolean) {
    this.isUserMuted = muted;
    parametersService.save({ enableAudioAlerts: !muted });
    this.listeners.forEach(cb => cb(this.isMuted()));
  }

  public toggleMute(): boolean {
    const next = !this.isMuted();
    this.setMuted(next);
    return next;
  }

  public onMuteChange(callback: (muted: boolean) => void): () => void {
    this.listeners.add(callback);
    callback(this.isMuted());
    return () => this.listeners.delete(callback);
  }

  /**
   * Synthesize a tactical dual-tone critical alarm (880Hz / 587Hz urgent warble)
   */
  private playCriticalSiren(ctx: AudioContext) {
    const now = ctx.currentTime;
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();

    osc.type = 'sawtooth';
    // Frequency oscillation: 880Hz -> 587Hz -> 880Hz -> 587Hz
    osc.frequency.setValueAtTime(880, now);
    osc.frequency.linearRampToValueAtTime(587, now + 0.15);
    osc.frequency.linearRampToValueAtTime(880, now + 0.30);
    osc.frequency.linearRampToValueAtTime(587, now + 0.45);
    osc.frequency.linearRampToValueAtTime(880, now + 0.60);

    gain.gain.setValueAtTime(0.001, now);
    gain.gain.linearRampToValueAtTime(0.18, now + 0.05);
    gain.gain.setValueAtTime(0.18, now + 0.55);
    gain.gain.exponentialRampToValueAtTime(0.001, now + 0.70);

    osc.connect(gain);
    gain.connect(ctx.destination);

    osc.start(now);
    osc.stop(now + 0.72);
  }

  /**
   * Synthesize a tactical warning double-beep (660Hz / 880Hz)
   */
  private playWarningBeep(ctx: AudioContext) {
    const now = ctx.currentTime;
    
    // Beep 1
    const osc1 = ctx.createOscillator();
    const gain1 = ctx.createGain();
    osc1.type = 'sine';
    osc1.frequency.setValueAtTime(660, now);
    gain1.gain.setValueAtTime(0.15, now);
    gain1.gain.exponentialRampToValueAtTime(0.001, now + 0.12);
    osc1.connect(gain1);
    gain1.connect(ctx.destination);
    osc1.start(now);
    osc1.stop(now + 0.13);

    // Beep 2
    const osc2 = ctx.createOscillator();
    const gain2 = ctx.createGain();
    osc2.type = 'sine';
    osc2.frequency.setValueAtTime(880, now + 0.16);
    gain2.gain.setValueAtTime(0.16, now + 0.16);
    gain2.gain.exponentialRampToValueAtTime(0.001, now + 0.30);
    osc2.connect(gain2);
    gain2.connect(ctx.destination);
    osc2.start(now + 0.16);
    osc2.stop(now + 0.31);
  }

  /**
   * Synthesize an ascending triad confirmation chime (523Hz -> 659Hz -> 784Hz)
   */
  private playSuccessChime(ctx: AudioContext) {
    const now = ctx.currentTime;
    const notes = [523.25, 659.25, 783.99]; // C5, E5, G5
    
    notes.forEach((freq, idx) => {
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      const startTime = now + idx * 0.11;

      osc.type = 'triangle';
      osc.frequency.setValueAtTime(freq, startTime);

      gain.gain.setValueAtTime(0.001, startTime);
      gain.gain.linearRampToValueAtTime(0.14, startTime + 0.02);
      gain.gain.exponentialRampToValueAtTime(0.001, startTime + 0.35);

      osc.connect(gain);
      gain.connect(ctx.destination);

      osc.start(startTime);
      osc.stop(startTime + 0.38);
    });
  }

  /**
   * Synthesize a tactical sonar ping for traffic spikes (1200Hz ping)
   */
  private playSonarPing(ctx: AudioContext) {
    const now = ctx.currentTime;
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();

    osc.type = 'sine';
    osc.frequency.setValueAtTime(1200, now);
    osc.frequency.exponentialRampToValueAtTime(600, now + 0.4);

    gain.gain.setValueAtTime(0.12, now);
    gain.gain.exponentialRampToValueAtTime(0.001, now + 0.45);

    osc.connect(gain);
    gain.connect(ctx.destination);

    osc.start(now);
    osc.stop(now + 0.46);
  }

  /**
   * Trigger an audio alert for a threat event
   */
  public playThreatAlert(severity: 'critical' | 'high' | 'medium' | 'low') {
    if (this.isMuted()) return;
    const now = Date.now();
    if (now - this.lastPlayedTime < this.MIN_COOLDOWN_MS) return;
    this.lastPlayedTime = now;

    const ctx = this.getAudioContext();
    if (!ctx) return;

    try {
      if (severity === 'critical') {
        this.playCriticalSiren(ctx);
      } else if (severity === 'high') {
        this.playWarningBeep(ctx);
      }
    } catch (e) {
      console.warn('Erro ao reproduzir alerta sonoro:', e);
    }
  }

  /**
   * Trigger confirmation chime when mitigation rule is successfully applied
   */
  public playMitigationSuccess() {
    if (this.isMuted()) return;
    const ctx = this.getAudioContext();
    if (!ctx) return;
    try {
      this.playSuccessChime(ctx);
    } catch (e) {}
  }

  /**
   * Trigger sonar ping on high-volume traffic spike
   */
  public playSpikePing() {
    if (this.isMuted()) return;
    const ctx = this.getAudioContext();
    if (!ctx) return;
    try {
      this.playSonarPing(ctx);
    } catch (e) {}
  }

  /**
   * Test alert sound explicitly on user demand (bypasses cooldown and mute)
   */
  public testSound(type: SoundEffectType = 'critical'): boolean {
    const ctx = this.getAudioContext();
    if (!ctx) return false;

    try {
      if (type === 'critical') {
        this.playCriticalSiren(ctx);
      } else if (type === 'warning') {
        this.playWarningBeep(ctx);
      } else if (type === 'success') {
        this.playSuccessChime(ctx);
      } else if (type === 'spike') {
        this.playSonarPing(ctx);
      }
      return true;
    } catch (e) {
      console.warn('Erro no teste sonoro:', e);
      return false;
    }
  }
}

export const soundAlertService = new SoundAlertService();
