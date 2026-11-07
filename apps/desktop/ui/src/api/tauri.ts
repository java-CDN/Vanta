import type { Backend, Unsubscribe } from './backend';
import type * as T from './types';

/** `invoke` from @tauri-apps/api/core; injectable for tests. Arguments use camelCase keys,
 *  which Tauri maps to the Rust command's snake_case parameters. */
export type Invoke = <R>(cmd: string, args?: Record<string, unknown>) => Promise<R>;
export type Listen = <P>(event: string, cb: (payload: P) => void) => Promise<Unsubscribe>;

/** Event names emitted by src-tauri (keep in sync with src-tauri/src/events.rs). */
export const EVENTS = {
  status: 'vanta://status',
  log: 'vanta://log',
  locked: 'vanta://locked',
  closeRequested: 'vanta://close-requested',
} as const;

export function tauriBackend(invoke: Invoke, listen: Listen): Backend {
  return {
    kind: 'tauri',
    appInfo: () => invoke('app_info'),
    createVault: password => invoke('create_vault', { password }),
    unlock: password => invoke('unlock', { password }),
    unlockWithRecovery: recoveryKey => invoke('unlock_with_recovery', { recoveryKey }),
    lock: () => invoke('lock'),
    changePassword: (current, next) => invoke('change_password', { current, newPassword: next }),
    listProfiles: (query, limit, offset) => invoke('list_profiles', { query, limit, offset }),
    folders: () => invoke('folders'),
    getProfile: id => invoke('get_profile', { id }),
    createProfile: profile => invoke('create_profile', { profile }),
    editProfile: (id, edit) => invoke('edit_profile', { id, edit }),
    deleteProfiles: ids => invoke('delete_profiles', { ids }),
    fingerprint: id => invoke('fingerprint', { id }),
    previewFingerprint: (os, locale, seed) => invoke('preview_fingerprint', { os, locale, seed }),
    regenerateFingerprint: (id, os) => invoke('regenerate_fingerprint', { id, os }),
    listProxies: () => invoke('list_proxies'),
    importProxies: (text, defaultScheme) => invoke('import_proxies', { text, defaultScheme }),
    deleteProxy: proxyId => invoke('delete_proxy', { proxyId }),
    assignProxy: (profileId, proxyId) => invoke('assign_proxy', { profileId, proxyId }),
    testProxy: proxyId => invoke('test_proxy', { proxyId }),
    launchProfile: id => invoke('launch_profile', { id }),
    stopProfile: id => invoke('stop_profile', { id }),
    runningProfiles: () => invoke('running_profiles'),
    runHealth: id => invoke('run_health', { id }),
    guardPolicy: id => invoke('guard_policy', { id }),
    setDohProvider: (id, doh) => invoke('set_doh_provider', { id, doh }),
    activityLog: query => invoke('activity_log', { query }),
    getSettings: () => invoke('get_settings'),
    setSettings: settings => invoke('set_settings', { settings }),
    reportActivity: () => invoke('report_activity'),
    quit: () => invoke('quit_app'),
    onStatus: cb => listen<T.StatusChange[]>(EVENTS.status, cb),
    onLog: cb => listen<T.LogEntry[]>(EVENTS.log, cb),
    onLocked: cb => listen<T.LockedEvent>(EVENTS.locked, cb),
    onCloseRequested: cb => listen<T.CloseRequest>(EVENTS.closeRequested, cb),
  };
}

/** The real backend, wired to @tauri-apps/api (loaded lazily so the mock build never ships it). */
export async function connectTauri(): Promise<Backend> {
  const core = await import('@tauri-apps/api/core');
  const ev = await import('@tauri-apps/api/event');
  const listen: Listen = async (name, cb) => ev.listen(name, e => cb(e.payload as never));
  return tauriBackend(core.invoke as Invoke, listen);
}
