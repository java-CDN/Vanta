import { describe, expect, it } from 'vitest';
import { tauriBackend, EVENTS } from '../src/api/tauri';
import { asCoreError, errorText } from '../src/api/backend';
import type { Backend } from '../src/api/backend';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

function capture() {
  const calls: [string, Record<string, unknown> | undefined][] = [];
  const listens: string[] = [];
  const b = tauriBackend(
    (async (cmd: string, args?: Record<string, unknown>) => { calls.push([cmd, args]); return null; }) as never,
    async (ev: string) => { listens.push(ev); return () => {}; },
  );
  return { b, calls, listens };
}

const ID = '7f1c6a52-0d0e-4f53-9d4c-2b8f1a9e3c11';

describe('tauri api mapping', () => {
  it('maps every method to its command and argument names', async () => {
    const { b, calls } = capture();
    const cases: [(b: Backend) => Promise<unknown>, string, Record<string, unknown> | undefined][] = [
      [x => x.appInfo(), 'app_info', undefined],
      [x => x.createVault('pw'), 'create_vault', { password: 'pw' }],
      [x => x.unlock('pw'), 'unlock', { password: 'pw' }],
      [x => x.unlockWithRecovery('K'), 'unlock_with_recovery', { recoveryKey: 'K' }],
      [x => x.lock(), 'lock', undefined],
      [x => x.changePassword('a', 'b'), 'change_password', { current: 'a', newPassword: 'b' }],
      [x => x.listProfiles('tag:a', 10, 5), 'list_profiles', { query: 'tag:a', limit: 10, offset: 5 }],
      [x => x.folders(), 'folders', undefined],
      [x => x.getProfile(ID), 'get_profile', { id: ID }],
      [x => x.createProfile({ name: 'n', seed: 'AB' }), 'create_profile', { profile: { name: 'n', seed: 'AB' } }],
      [x => x.editProfile(ID, { notes: 'x' }), 'edit_profile', { id: ID, edit: { notes: 'x' } }],
      [x => x.deleteProfiles([ID]), 'delete_profiles', { ids: [ID] }],
      [x => x.fingerprint(ID), 'fingerprint', { id: ID }],
      [x => x.previewFingerprint('windows10', 'de-DE', 'FF'), 'preview_fingerprint', { os: 'windows10', locale: 'de-DE', seed: 'FF' }],
      [x => x.regenerateFingerprint(ID, null), 'regenerate_fingerprint', { id: ID, os: null }],
      [x => x.listProxies(), 'list_proxies', undefined],
      [x => x.importProxies('h:1', 'socks5'), 'import_proxies', { text: 'h:1', defaultScheme: 'socks5' }],
      [x => x.deleteProxy('p1'), 'delete_proxy', { proxyId: 'p1' }],
      [x => x.assignProxy(ID, null), 'assign_proxy', { profileId: ID, proxyId: null }],
      [x => x.testProxy('p1'), 'test_proxy', { proxyId: 'p1' }],
      [x => x.launchProfile(ID), 'launch_profile', { id: ID }],
      [x => x.stopProfile(ID), 'stop_profile', { id: ID }],
      [x => x.runningProfiles(), 'running_profiles', undefined],
      [x => x.runHealth(ID), 'run_health', { id: ID }],
      [x => x.guardPolicy(ID), 'guard_policy', { id: ID }],
      [x => x.setDohProvider(ID, 'quad9'), 'set_doh_provider', { id: ID, doh: 'quad9' }],
      [x => x.activityLog({ kinds: ['health_run'], limit: 12 }), 'activity_log', { query: { kinds: ['health_run'], limit: 12 } }],
      [x => x.getSettings(), 'get_settings', undefined],
      [x => x.setSettings({ autolock_minutes: 5, theme: 'dark', max_launch: 12, confirm_delete: true, engine_path: null, ip_echo_url: null }), 'set_settings', { settings: { autolock_minutes: 5, theme: 'dark', max_launch: 12, confirm_delete: true, engine_path: null, ip_echo_url: null } }],
      [x => x.reportActivity(), 'report_activity', undefined],
      [x => x.quit(), 'quit_app', undefined],
    ];
    for (const [f, cmd, args] of cases) { calls.length = 0; await f(b); expect(calls).toEqual([[cmd, args]]); }
  });

  it('uses exactly the commands the shell registers and permits', () => {
    const { b, calls } = capture();
    const root = fileURLToPath(new URL('../../src-tauri/', import.meta.url));
    const build = readFileSync(root + 'build.rs', 'utf8');
    const main = readFileSync(root + 'src/main.rs', 'utf8');
    const cap = JSON.parse(readFileSync(root + 'capabilities/default.json', 'utf8')) as { permissions: string[] };
    const allowed = [...build.matchAll(/^\s+"([a-z_]+)",$/gm)].map(m => m[1]).sort();
    const registered = [...main.matchAll(/commands::([a-z_]+),/g)].map(m => m[1]).sort();
    const granted = cap.permissions.filter(p => p.startsWith('allow-')).map(p => p.slice(6).replace(/-/g, '_')).sort();
    // Every Backend method invokes one command; collect them.
    const all = Object.entries(b).filter(([k, v]) => typeof v === 'function' && !k.startsWith('on'));
    return Promise.all(all.map(([, f]) => (f as (...a: unknown[]) => Promise<unknown>)('a', 'b', 'c'))).then(() => {
      const used = [...new Set(calls.map(c => c[0]))].sort();
      expect(used).toEqual(allowed);
      expect(registered).toEqual(allowed);
      expect(granted).toEqual(allowed);
      expect(cap.permissions.filter(p => !p.startsWith('allow-'))).toEqual(['core:event:allow-listen', 'core:event:allow-unlisten']);
    });
  });

  it('subscribes to the shell events', async () => {
    const { b, listens } = capture();
    await b.onStatus(() => {}); await b.onLog(() => {}); await b.onLocked(() => {}); await b.onCloseRequested(() => {});
    expect(listens).toEqual([EVENTS.status, EVENTS.log, EVENTS.locked, EVENTS.closeRequested]);
    const ev = readFileSync(fileURLToPath(new URL('../../src-tauri/src/events.rs', import.meta.url)), 'utf8');
    for (const name of Object.values(EVENTS)) expect(ev).toContain(`"${name}"`);
  });
});

describe('error mapping', () => {
  it('passes CoreError through and wraps anything else', () => {
    expect(asCoreError({ kind: 'locked' })).toEqual({ kind: 'locked' });
    expect(asCoreError(new Error('boom'))).toEqual({ kind: 'storage', message: 'boom' });
    expect(asCoreError('x')).toEqual({ kind: 'storage', message: 'x' });
  });
  it('turns every kind into text', () => {
    expect(errorText({ kind: 'crypto' })).toBe('Wrong password or corrupted data.');
    expect(errorText({ kind: 'blocked', reasons: [{ code: 'proxy_offline', message: 'launch blocked: proxy offline' }, { code: 'health_missing', message: 'launch blocked: no health check' }] })).toBe('proxy offline; no health check');
    expect(errorText({ kind: 'invalid', message: 'name is required' })).toBe('Name is required');
    expect(errorText({ kind: 'version_mismatch', expected: '156.0.8078.79' })).toContain('156.0.8078.79');
    expect(errorText({ kind: 'engine_exited', code: null })).toContain('none');
  });
});
