import type { LogKind, OsKind, ProfileStatus, ProxyState, ProxyView } from '../api/types';

const MON = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
export const pad = (n: number) => String(n).padStart(2, '0');
export const hm = (d: Date) => `${pad(d.getHours())}:${pad(d.getMinutes())}`;
export const hms = (d: Date) => `${hm(d)}:${pad(d.getSeconds())}`;
export function dayStart(t: number) { const d = new Date(t); d.setHours(0, 0, 0, 0); return d.getTime(); }
export function relDay(t: number | null | undefined): string {
  if (!t) return 'Never';
  const d = new Date(t); const today = dayStart(Date.now()); const ds = dayStart(t);
  if (ds === today) return 'Today ' + hm(d);
  if (ds === today - 864e5) return 'Yesterday ' + hm(d);
  return `${MON[d.getMonth()]} ${d.getDate()}, ${hm(d)}`;
}
export const dateLabel = (t: number) => { const d = new Date(t); return `${MON[d.getMonth()]} ${d.getDate()}, ${d.getFullYear()}`; };

export const osLabel = (o: OsKind) => (o === 'windows11' ? 'Win 11' : 'Win 10');
export const osLong = (o: OsKind) => (o === 'windows11' ? 'Windows 11' : 'Windows 10');
export const scoreCls = (n: number) => (n >= 90 ? 'g' : n >= 75 ? 'y' : 'r');
export const statusLabel = (s: ProfileStatus) => s.charAt(0).toUpperCase() + s.slice(1);

export function proxyName(x: ProxyView): string { return x.label || `${x.host}:${x.port}`; }
export const schemeLabel = (s: string) => (s === 'socks5' ? 'SOCKS5' : s.toUpperCase());

export function proxyStatus(s: ProxyState): 'ok' | 'slow' | 'offline' | 'untested' {
  if (s.state === 'online') return s.latency_ms > 300 ? 'slow' : 'ok';
  if (s.state === 'offline') return 'offline';
  return 'untested';
}
export const offlineReason = (r: string) =>
  ({ unreachable: 'unreachable', timeout: 'timed out', auth_failed: 'login refused', protocol_error: 'protocol error' } as Record<string, string>)[r] || r;

/** Activity-log kinds as the prototype's event types and titles. */
export const LOG_INFO: Record<LogKind, { type: string; title: string; icon: string; cls: string }> = {
  profile_launch: { type: 'launch', title: 'Launched', icon: 'play', cls: 'ok' },
  profile_stop: { type: 'stop', title: 'Stopped', icon: 'stop', cls: '' },
  profile_crash: { type: 'stop', title: 'Profile crashed', icon: 'alert', cls: 'bad' },
  vault_unlock: { type: 'vault', title: 'Vault unlocked', icon: 'lock', cls: 'acc' },
  vault_lock: { type: 'vault', title: 'Vault locked', icon: 'lock', cls: 'acc' },
  proxy_failure: { type: 'proxy', title: 'Proxy check failed', icon: 'globe', cls: 'warn' },
  proxy_reconnect: { type: 'proxy', title: 'Proxy reconnected', icon: 'globe', cls: 'ok' },
  blocked_event: { type: 'blocked', title: 'Blocked request', icon: 'shield', cls: 'warn' },
  kill_switch: { type: 'blocked', title: 'Kill switch tripped', icon: 'shield', cls: 'bad' },
  launch_blocked: { type: 'blocked', title: 'Launch blocked', icon: 'shield', cls: 'warn' },
  health_run: { type: 'health', title: 'Health check', icon: 'pulse', cls: '' },
};

/** Filter tabs of the Activity Log and the kinds each one asks the backend for. */
export const LOG_TYPES: [string, string, LogKind[]][] = [
  ['all', 'All', []],
  ['launch', 'Launches', ['profile_launch', 'profile_stop', 'profile_crash']],
  ['blocked', 'Blocked', ['blocked_event', 'kill_switch', 'launch_blocked']],
  ['proxy', 'Proxy', ['proxy_failure', 'proxy_reconnect']],
  ['vault', 'Vault', ['vault_unlock', 'vault_lock']],
  ['health', 'Health', ['health_run']],
];

export const AUTOLOCK_OPTIONS: [number, string][] = [[1, '1 min'], [5, '5 min'], [10, '10 min'], [15, '15 min'], [30, '30 min'], [60, '1 hour'], [0, 'Never']];
export const autolockLabel = (m: number) => (m ? `auto-lock ${AUTOLOCK_OPTIONS.find(o => o[0] === m)?.[1] ?? m + ' min'}` : 'auto-lock off');

/** Random 64-bit seed as 16 hex digits (crypto RNG). */
export function newSeed(): string {
  const b = new Uint8Array(8);
  crypto.getRandomValues(b);
  return Array.from(b, x => x.toString(16).padStart(2, '0')).join('').toUpperCase();
}

/** Profile names: letters, digits, dot, dash, underscore; 1–40 characters (prototype rule). */
export function nameError(name: string, taken: (n: string) => boolean): string {
  if (!name) return 'Name is required.';
  if (name.length > 40) return 'Use 40 characters or fewer.';
  if (!/^[a-z0-9][a-z0-9._-]*$/i.test(name)) return 'Use letters, numbers, dot, dash or underscore (no spaces).';
  if (taken(name)) return 'A profile with this name already exists.';
  return '';
}

export function cleanTag(t: string): string { return t.trim().toLowerCase().replace(/[^a-z0-9_-]/g, ''); }
