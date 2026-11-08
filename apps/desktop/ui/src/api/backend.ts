import type * as T from './types';

export type Unsubscribe = () => void;

/** Everything the UI can ask of Vanta. One implementation talks to the Tauri shell
 *  (tauri.ts), the other is an in-memory mock for browser development and tests (mock.ts). */
export interface Backend {
  readonly kind: 'tauri' | 'mock';
  appInfo(): Promise<T.AppInfo>;
  // vault
  createVault(password: string): Promise<T.VaultCreated>;
  unlock(password: string): Promise<T.UnlockReport>;
  unlockWithRecovery(recoveryKey: string): Promise<T.UnlockReport>;
  lock(): Promise<void>;
  changePassword(current: string, next: string): Promise<void>;
  // profiles
  listProfiles(query: string, limit: number, offset: number): Promise<T.ProfilePage>;
  folders(): Promise<[string, number][]>;
  getProfile(id: string): Promise<T.ProfileDetail>;
  createProfile(p: T.NewProfile): Promise<T.ProfileMeta>;
  editProfile(id: string, edit: T.ProfileEdit): Promise<T.ProfileMeta>;
  deleteProfiles(ids: string[]): Promise<number>;
  // fingerprint
  fingerprint(id: string): Promise<T.FingerprintView>;
  previewFingerprint(os: T.OsKind | null, locale: string | null, seed: string): Promise<T.FingerprintView>;
  regenerateFingerprint(id: string, os: T.OsKind | null): Promise<T.ProfileMeta>;
  // proxies
  listProxies(): Promise<T.ProxyView[]>;
  importProxies(text: string, defaultScheme: T.ProxyScheme): Promise<T.ImportResult>;
  deleteProxy(proxyId: string): Promise<void>;
  assignProxy(profileId: string, proxyId: string | null): Promise<T.AssignResult>;
  testProxy(proxyId: string): Promise<T.ProxyView>;
  // launch & health
  /** `confirmed`: the user confirmed one more attempt after repeated failed launches
   *  (the plain call rejects with `confirm_required` then; see MAX_FAILED_LAUNCHES). */
  launchProfile(id: string, confirmed?: boolean): Promise<T.LaunchInfo>;
  stopProfile(id: string): Promise<void>;
  runningProfiles(): Promise<string[]>;
  runHealth(id: string): Promise<T.HealthResult>;
  // network guard
  guardPolicy(id: string): Promise<T.GuardPolicy>;
  setDohProvider(id: string, doh: T.DohProvider): Promise<T.GuardPolicy>;
  // activity log
  activityLog(q: T.LogQuery): Promise<T.LogPage>;
  // shell
  getSettings(): Promise<T.Settings>;
  setSettings(s: T.Settings): Promise<T.Settings>;
  /** Keyboard/mouse activity inside Vanta (throttled by the caller); resets the idle lock. */
  reportActivity(): Promise<void>;
  quit(): Promise<void>;
  // pushed events
  onStatus(cb: (changes: T.StatusChange[]) => void): Promise<Unsubscribe>;
  onLog(cb: (entries: T.LogEntry[]) => void): Promise<Unsubscribe>;
  onLocked(cb: (e: T.LockedEvent) => void): Promise<Unsubscribe>;
  onCloseRequested(cb: (e: T.CloseRequest) => void): Promise<Unsubscribe>;
}

/** Failed launches in a row (gate block, exit 86/87, crash in the first 3 s) after which
 *  the next attempt needs the user's confirmation (vanta_core::MAX_FAILED_LAUNCHES). */
export const MAX_FAILED_LAUNCHES = 3;

/** Errors from the backend are `CoreError` values; anything else is wrapped. */
export function asCoreError(e: unknown): T.CoreError {
  if (e && typeof e === 'object' && 'kind' in e && typeof (e as { kind: unknown }).kind === 'string') return e as T.CoreError;
  return { kind: 'storage', message: e instanceof Error ? e.message : String(e) };
}

/** Text ready to show for a backend error. */
export function errorText(e: unknown): string {
  const c = asCoreError(e);
  switch (c.kind) {
    case 'not_initialized': return 'The vault has not been created yet.';
    case 'already_initialized': return 'The vault already exists.';
    case 'locked': return 'The vault is locked.';
    case 'crypto': return 'Wrong password or corrupted data.';
    case 'not_found': return `Not found: ${c.message}`;
    case 'invalid': return c.message.charAt(0).toUpperCase() + c.message.slice(1);
    case 'already_running': return 'The profile is already running.';
    case 'not_running': return 'The profile is not running.';
    case 'blocked': return c.reasons.map(r => r.message.replace(/^launch blocked: /, '')).join('; ');
    case 'bad_config_signature': return 'The engine rejected the launch config signature (exit 86).';
    case 'version_mismatch': return `Persona version does not match the installed engine ${c.expected} (exit 87, C030).`;
    case 'engine_exited': return `The engine exited during start-up (code ${c.code ?? 'none'}).`;
    case 'unsupported': return c.message;
    case 'storage': return `Storage error: ${c.message}`;
    case 'network': return `Network error: ${c.message}`;
    case 'engine_integrity': return `Engine check: ${c.message.charAt(0).toUpperCase()}${c.message.slice(1)}.`;
    case 'confirm_required': return `The last ${c.failures} launches failed in a row (last: ${c.last_error}).`;
  }
}
