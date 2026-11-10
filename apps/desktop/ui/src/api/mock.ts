// In-memory backend for browser development and tests (`npm run dev:mock`). Behaves like
// vanta-core where the UI can tell (errors, gates, statuses, log kinds), with the
// prototype's demo data. Never shipped in the Tauri build.

import { MAX_FAILED_LAUNCHES, type Backend, type Unsubscribe } from './backend';
import type * as T from './types';
import { COUNTRIES, DEVICES, ENGINE, FONTS_WIN10, FONTS_WIN11, GPUS, PROFILE_SEED, PROXY_SEED, hashStr } from './demo';
import { CHECKS } from '../lib/catalog';
import { matches, parse, SearchError } from '../lib/search';
import { parseLine, parseList } from '../lib/proxyparse';
import { buildPreset } from '../lib/presets';
import { echoUrlProblem } from '../lib/echo';

export interface MockOptions {
  /** Start without a vault (first-run screen). */
  fresh?: boolean;
  /** Start unlocked. */
  unlocked?: boolean;
  /** Bundled-engine check to report: `failed` blocks launches like vanta-core. */
  engineCheck?: 'failed';
  /** Extra generated profiles (virtual list test). */
  extraProfiles?: number;
  /** Offline GeoIP database state (default: ready). */
  geoip?: 'not_bundled' | 'failed';
  /** Delay scale (0 = instant, for unit tests). */
  speed?: number;
}

/** `geo`: 'ok' = matched to its proxy's exit, 'tz:<zone>' = fixed elsewhere, 'none' = never matched. `lang`: locale kept when matched without languages. */
interface MProfile { meta: T.ProfileMeta; seed: number; device: string; geo: 'ok' | 'none' | string; lang?: string; doh: T.DohProvider; health: T.HealthSummary | null }
interface MProxy { view: T.ProxyView; cc: string; ip: string; latency: number | null; kind: 'ok' | 'slow' | 'offline' }

const UA = (major: string) => `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${major}.0.0.0 Safari/537.36`;
const crit = (id: string) => CHECKS.find(c => c.id === id)?.severity === 'critical';

let idc = 0;
const mkId = (prefix: string) => {
  idc++;
  const h = (hashStr(prefix + idc) >>> 0).toString(16).padStart(8, '0');
  return `${h}-${(idc & 0xffff).toString(16).padStart(4, '0')}-4000-8000-${(hashStr(String(idc)) >>> 0).toString(16).padStart(12, '0').slice(0, 12)}`;
};

export function mockBackend(opts: MockOptions = {}): Backend {
  const speed = opts.speed ?? 1;
  const wait = (ms: number) => new Promise<void>(r => setTimeout(r, ms * speed));
  const now = Date.now();
  let initialized = !opts.fresh;
  let unlocked = !!opts.unlocked && initialized;
  let password = 'demo';
  let recovery = '';
  const geoip: T.GeoDbStatus = opts.geoip === 'not_bundled' ? { state: 'not_bundled' } : opts.geoip === 'failed' ? { state: 'failed', message: 'GeoIP database failed its integrity check' }
    : { state: 'ready', info: { database_type: 'DBIP-City-Lite', release: '2026-11', license: 'CC BY 4.0', attribution: 'IP geolocation by DB-IP (https://db-ip.com)' } };
  const engineCheck: T.EngineCheck = opts.engineCheck === 'failed' ? { state: 'failed', message: 'chrome.dll differs' } : { state: 'not_bundled' };
  /** Consecutive failed launches per profile (like vanta-core). */
  const failed = new Map<string, { n: number; last: string }>();
  let settings: T.Settings = { autolock_minutes: 10, theme: 'dark', max_launch: 12, confirm_delete: true, engine_path: null, ip_echo_url: null, ip_info_url: null, speed_test_url: null };
  let lastActive = Date.now();
  const listeners = { status: new Set<(c: T.StatusChange[]) => void>(), log: new Set<(e: T.LogEntry[]) => void>(), locked: new Set<(e: T.LockedEvent) => void>(), close: new Set<(e: T.CloseRequest) => void>() };
  const sub = <F>(set: Set<F>, cb: F): Promise<Unsubscribe> => { set.add(cb); return Promise.resolve(() => { set.delete(cb); }); };

  // ---- data -------------------------------------------------------------------------
  const proxies: MProxy[] = PROXY_SEED.map(([name, scheme, provider, cc, ip, lat, kind]) => {
    const port = scheme === 'http' ? 8080 : 12000 + (hashStr(name) % 900);
    const user = provider === 'Own server' ? 'vanta' : `user-${name.replace(/-/g, '')}-session-${(hashStr(name) % 0xffff).toString(16)}`;
    const host = ip;
    const checked = now - (2 + (hashStr(name) % 50)) * 60000;
    const state: T.ProxyState = kind === 'offline' ? { state: 'offline', checked_ms: checked, reason: 'timeout' } : { state: 'online', checked_ms: checked, latency_ms: lat ?? 0 };
    return { cc, ip, latency: lat, kind, view: { id: mkId('px'), scheme, host, port, username: user, has_password: true, label: name, state, display: `${scheme}://${user}:***@${host}:${port}`, preset: null, checks: null } };
  });
  const pxByLabel = (l: string) => proxies.find(p => p.view.label === l)!;
  const profiles: MProfile[] = PROFILE_SEED.map(([name, folder, tags, os, px, health, status, ago, device, geo, notes]) => {
    const p = pxByLabel(px);
    const id = mkId('p');
    const meta: T.ProfileMeta = { id, name, folder, tags, os, proxy_id: p.view.id, exit_ip: p.ip, country: p.cc, health, status, color: '', notes, created_ms: now - (ago + 60 * 24 * 20) * 60000, last_opened_ms: now - ago * 60000 };
    return { meta, seed: hashStr(name + 'seed'), device, geo, doh: 'cloudflare', health: { profile_id: id, score: health, blocked: health < 60, failing: health < 60 ? ['H06'] : [], engine: ENGINE, proxy_id: p.view.id, ts_ms: now - 3600_000 } };
  });
  for (let i = 0; i < (opts.extraProfiles ?? 0); i++) {
    const p = proxies[i % proxies.length]; const os = i % 2 ? 'windows10' : 'windows11';
    const name = `bulk-${String(i).padStart(5, '0')}`;
    const meta: T.ProfileMeta = { id: mkId('b'), name, folder: 'Research', tags: [['shop', 'ads', 'social', 'qa'][i % 4]], os, proxy_id: p.view.id, exit_ip: p.ip, country: p.cc, health: 60 + (i % 40), status: 'stopped', color: '', notes: '', created_ms: now - i * 1000, last_opened_ms: null };
    profiles.push({ meta, seed: hashStr(name), device: DEVICES[i % DEVICES.length].id, geo: 'ok', doh: 'cloudflare', health: null });
  }

  const log: T.LogEntry[] = [];
  const pushLog = (kind: T.LogKind, profile: string | null, detail: string, ts = Date.now(), emit = true) => {
    const e = { seq: log.length, ts_ms: ts, kind, profile, detail };
    log.push(e);
    if (emit && unlocked) listeners.log.forEach(f => f([e]));
    return e;
  };
  (() => {
    const ev: [number, T.LogKind, string | null, string][] = [];
    const ids = profiles.slice(0, 25).map(p => p.meta.id);
    for (let d = 20; d >= 1; d--) {
      const base = d * 1440;
      ev.push([base + 600, 'vault_unlock', null, 'unlocked with password']);
      for (let k = 0; k < 4; k++) {
        const id = ids[(d * 3 + k * 5) % ids.length];
        ev.push([base + 540 - k * 70, 'profile_launch', id, `engine ${ENGINE} pid ${4000 + k}, relay 127.0.0.1:${49700 + k}`]);
        ev.push([base + 500 - k * 70, 'profile_stop', id, 'stopped by user']);
      }
      if (d === 4) ev.push([base + 250, 'launch_blocked', ids[9], 'proxy_offline']);
      ev.push([base + 30, 'vault_lock', null, 'locked: 10 min idle']);
    }
    ev.push([300, 'vault_unlock', null, 'unlocked with password']);
    ev.push([290, 'proxy_failure', null, 'proxy socks5://vanta:***@203.0.113.120 check failed: timed out']);
    ev.push([240, 'health_run', ids[9], 'score 40 (blocks launch); failing: H06']);
    ev.push([230, 'launch_blocked', ids[9], 'proxy_offline']);
    ev.push([200, 'profile_launch', ids[8], `engine ${ENGINE} pid 5120, relay 127.0.0.1:49731`]);
    ev.push([150, 'profile_launch', ids[6], `engine ${ENGINE} pid 5188, relay 127.0.0.1:49744`]);
    ev.push([149, 'blocked_event', ids[6], 'LAN target 192.168.1.1 refused']);
    ev.push([60, 'health_run', ids[0], 'score 96; failing: none']);
    ev.push([52, 'profile_launch', ids[3], `engine ${ENGINE} pid 6012, relay 127.0.0.1:49802`]);
    ev.push([45, 'blocked_event', ids[3], 'IPv6 target refused (relay is IPv4 only)']);
    ev.push([7, 'profile_launch', ids[1], `engine ${ENGINE} pid 6420, relay 127.0.0.1:49811`]);
    ev.push([6, 'blocked_event', ids[1], 'UDP (QUIC) refused: proxy tunnel is TCP only']);
    ev.push([5, 'profile_launch', ids[0], `engine ${ENGINE} pid 6502, relay 127.0.0.1:49820`]);
    ev.push([4, 'blocked_event', ids[0], 'non-proxied UDP (WebRTC host candidate) refused']);
    ev.sort((a, b) => b[0] - a[0]).forEach(([m, k, p, d]) => pushLog(k, p, d, now - m * 60000, false));
  })();

  // ---- helpers ----------------------------------------------------------------------
  const need = () => { if (!initialized) throw { kind: 'not_initialized' }; if (!unlocked) throw { kind: 'locked' }; };
  const prof = (id: string) => { const p = profiles.find(x => x.meta.id === id); if (!p) throw { kind: 'not_found', message: `profile ${id}` }; return p; };
  const px = (id: string) => { const p = proxies.find(x => x.view.id === id); if (!p) throw { kind: 'not_found', message: `proxy ${id}` }; return p; };
  const emitStatus = (c: T.StatusChange[]) => listeners.status.forEach(f => f(c));
  const pick = (os: T.OsKind | null, seed: number) => {
    const list = DEVICES.filter(d => !os || d.os.includes(os));
    const tot = list.reduce((a, d) => a + d.w, 0);
    let x = (seed % 10007) / 10007 * tot;
    for (const d of list) { x -= d.w; if (x <= 0) return d; }
    return list[0];
  };
  const view = (os: T.OsKind, deviceId: string, seed: number, locale: string, geo: { cc: string; tz: string } | null): T.FingerprintView => {
    const d = DEVICES.find(x => x.id === deviceId) ?? DEVICES[0];
    const g = GPUS[d.gpu];
    const [w, h] = d.res.split('x').map(Number);
    const taskbar = os === 'windows11' ? 48 : 40;
    const major = ENGINE.split('.')[0];
    const langs = locale.startsWith('en') ? [locale, 'en'] : [locale, locale.split('-')[0], 'en-US', 'en'];
    const rules: T.RuleView[] = Array.from({ length: 30 }, (_, i) => ({ id: `C${String(i + 1).padStart(3, '0')}`, level: 'pass' as const, message: '' }));
    const msg: Record<string, string> = {
      C001: 'UA OS token is Windows NT 10.0; Win64; x64', C002: 'navigator.platform = Win32', C003: 'UA-CH platform "Windows"',
      C004: 'WebGL renderer uses ANGLE Direct3D11', C005: 'Hardware GPU, no software renderer', C006: `WebGL vendor ${g.v} = renderer maker ${g.v}`,
      C007: 'WebGPU vendor matches the GPU', C008: 'Available screen area fits inside the screen', C009: `Screen ${w} × ${h} is a desktop size`,
      C010: `DPR ${d.dpr} is a Windows scaling step`, C011: 'Color depth 24', C012: 'Core Windows fonts present',
      C013: 'No fonts from another OS or Windows version', C014: `${d.cores} logical cores is a real CPU layout`, C015: `deviceMemory ${d.mem} (Chrome bucket)`,
      C016: 'maxTouchPoints 0 on a desktop record', C017: 'Desktop flags consistent', C018: geo ? `Timezone ${geo.tz} = exit country ${geo.cc}` : 'Note: no location yet; timezone is checked against the exit IP at launch',
      C019: `Locale ${locale} = navigator.languages[0]`, C020: 'Accept-Language = navigator.languages', C021: `platformVersion fits ${os === 'windows11' ? 'Windows 11' : 'Windows 10'}`,
      C022: `Architecture ${g.arm ? 'arm' : 'x86'}, bitness 64`, C023: 'Media device counts plausible', C024: 'WebRTC policy disable_non_proxied_udp',
      C025: `Note: device record weight ${d.w} of 93`, C026: 'Noise seeds stable and non-zero', C027: 'ANGLE renderer string well-formed',
      C028: 'GPU family matches CPU architecture', C029: `Taskbar gap ${taskbar} px`, C030: `UA / UA-CH version ${major} = installed engine ${ENGINE}`,
    };
    rules.forEach(r => { r.message = msg[r.id]; if (r.id === 'C025' || (r.id === 'C018' && !geo)) r.level = 'note'; });
    return {
      device_id: d.id, os, engine: ENGINE, user_agent: UA(major),
      sec_ch_ua: `"Not:A-Brand";v="8", "Chromium";v="${major}", "Google Chrome";v="${major}"`,
      navigator_platform: 'Win32', ua_platform: 'Windows', platform_version: os === 'windows10' ? '10.0.0' : ['15.0.0', '19.0.0', '14.0.0'][seed % 3],
      architecture: g.arm ? 'arm' : 'x86', bitness: '64', screen_width: w, screen_height: h, avail_width: w, avail_height: h - taskbar, color_depth: 24,
      device_pixel_ratio: d.dpr, hardware_concurrency: d.cores, device_memory: d.mem, max_touch_points: 0,
      gpu_vendor: `Google Inc. (${g.v})`, gpu_renderer: `ANGLE (${g.v}, ${g.name} Direct3D11 vs_5_0 ps_5_0, D3D11)`, webgpu_vendor: g.v.toLowerCase(), webgpu_arch: g.arch,
      fonts: os === 'windows11' ? FONTS_WIN11 : FONTS_WIN10, microphones: 1 + (seed % 2), cameras: seed % 2, speakers: 1 + (seed % 3),
      locale, languages: langs, accept_language: langs.map((l, i) => (i ? `${l};q=${(1 - i * 0.1).toFixed(1)}` : l)).join(','),
      timezone: geo?.tz ?? null, country: geo?.cc ?? null, latitude: geo ? COUNTRIES[geo.cc]?.lat ?? null : null, longitude: geo ? COUNTRIES[geo.cc]?.lng ?? null : null,
      canvas: 'noise', webgl_image: 'noise', audio: 'noise', webrtc_policy: 'disable_non_proxied_udp',
      seed_prefix: (seed >>> 0).toString(16).toUpperCase().padStart(8, '0').slice(0, 4), rules,
    };
  };
  const profView = (p: MProfile) => {
    const proxy = p.meta.proxy_id ? proxies.find(x => x.view.id === p.meta.proxy_id) : undefined;
    let geo: { cc: string; tz: string } | null = null;
    if (p.geo === 'ok' && proxy) geo = { cc: proxy.cc, tz: COUNTRIES[proxy.cc].tz };
    else if (p.geo.startsWith('tz:')) { const tz = p.geo.slice(3); const cc = Object.keys(COUNTRIES).find(k => COUNTRIES[k].tz === tz) ?? 'US'; geo = { cc, tz }; }
    const locale = p.lang ?? (p.geo === 'none' ? 'en-US' : geo ? COUNTRIES[geo.cc].locale : 'en-US');
    const v = view(p.meta.os, p.device, p.seed, locale, geo);
    if (geo && proxy && geo.cc !== proxy.cc) {
      const r = v.rules.find(x => x.id === 'C018')!;
      r.level = 'fail'; r.message = `Timezone ${geo.tz} does not match exit country ${proxy.cc}`;
    }
    return v;
  };
  const display = (v: T.ProxyView) => v.username ? `${v.scheme}://${v.username}:***@${v.host}:${v.port}` : `${v.scheme}://${v.host}:${v.port}`;
  /** Like vanta-core `proxy_form`: valid host/port, label ≤ 64, username built from the preset. */
  const checkForm = async (form: T.ProxyForm) => {
    const host = form.host.trim().replace(/^\[|\]$/g, '');
    const r = parseLine(`${form.scheme}://${host.includes(':') ? `[${host}]` : host}:${form.port}`, 1, form.scheme);
    if (!r || r.err) throw { kind: 'invalid', message: r?.err ?? 'missing host' };
    const label = form.label.trim();
    if ([...label].length > 64) throw { kind: 'invalid', message: 'label is longer than 64 characters' };
    let username = form.username?.trim() || null; let preset: T.ProviderPreset | null = null;
    if (form.preset) { const b = await buildPreset(form.preset); preset = b.preset; username = b.username; }
    return { scheme: form.scheme, host: r.host!.toLowerCase(), port: r.port!, label, username, preset };
  };
  const sharedWith = (profileId: string, proxyId: string) => {
    const t = px(proxyId).view;
    return profiles.filter(o => o.meta.id !== profileId && o.meta.proxy_id && (() => { const v = px(o.meta.proxy_id!).view; return v.scheme === t.scheme && v.host === t.host && v.port === t.port && v.username === t.username; })()).map(o => o.meta.id);
  };
  const doLock = (reason: T.LockedEvent['reason']) => {
    if (!unlocked) return;
    pushLog('vault_lock', null, reason === 'idle' ? `locked: ${settings.autolock_minutes} min idle` : 'locked by user', Date.now(), false);
    unlocked = false;
    listeners.locked.forEach(f => f({ reason }));
  };
  if (typeof window !== 'undefined' && speed > 0) {
    setInterval(() => {
      if (unlocked && settings.autolock_minutes && Date.now() - lastActive > settings.autolock_minutes * 60000) doLock('idle');
    }, 1000);
  }
  const score = (problems: T.CheckProblem[]) => {
    let s = 100; let c = false;
    for (const p of problems) { if (p.outcome === 'warn') s -= 4; else { s -= 12; if (crit(p.id)) c = true; } }
    s = Math.max(0, s); return c ? Math.min(s, 40) : s;
  };
  const clone = <V>(v: V): V => JSON.parse(JSON.stringify(v));

  const b: Backend = {
    kind: 'mock',
    async appInfo() {
      return { app_version: '0.1.0', initialized, unlocked, engine_version: ENGINE, engine_path: settings.engine_path ?? '%LOCALAPPDATA%\\Programs\\Vanta\\engine\\vanta-chromium.exe', engine_found: engineCheck.state !== 'not_bundled', engine_check: clone(engineCheck), geoip: clone(geoip), data_dir: '%LOCALAPPDATA%\\Vanta', log_integrity: unlocked ? { state: 'ok' } : null, mock: true };
    },
    async createVault(pw) {
      if (initialized) throw { kind: 'already_initialized' };
      if (pw.length < 8) throw { kind: 'invalid', message: 'master password must have at least 8 characters' };
      await wait(700);
      initialized = true; unlocked = true; password = pw; lastActive = Date.now();
      const g = () => Array.from({ length: 4 }, () => 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'[Math.floor(Math.random() * 32)]).join('');
      recovery = Array.from({ length: 8 }, g).join('-');
      pushLog('vault_unlock', null, 'vault created');
      return { recovery_key: recovery };
    },
    async unlock(pw) {
      if (!initialized) throw { kind: 'not_initialized' };
      await wait(pw ? 700 : 150);
      if (!pw || pw.toLowerCase() === 'wrong' || (password !== 'demo' && pw !== password)) throw { kind: 'crypto' };
      unlocked = true; lastActive = Date.now();
      pushLog('vault_unlock', null, 'unlocked with password');
      return { log_integrity: { state: 'ok' }, migrated_proxies: 0 };
    },
    async unlockWithRecovery(key) {
      await wait(700);
      if (!recovery || key.trim().toUpperCase() !== recovery) throw { kind: 'crypto' };
      unlocked = true; lastActive = Date.now();
      pushLog('vault_unlock', null, 'unlocked with recovery key');
      return { log_integrity: { state: 'ok' }, migrated_proxies: 0 };
    },
    async lock() { doLock('user'); },
    async changePassword(cur, next) {
      need(); await wait(500);
      const isRecovery = !!recovery && cur.replace(/[^a-z0-9]/gi, '').toUpperCase() === recovery.replace(/-/g, '');
      if (!isRecovery && (password !== 'demo' ? cur !== password : !cur || cur.toLowerCase() === 'wrong')) throw { kind: 'crypto' };
      if (next.length < 8) throw { kind: 'invalid', message: 'master password must have at least 8 characters' };
      password = next; pushLog('vault_unlock', null, 'master password changed');
    },
    async listProfiles(query, limit, offset) {
      let q;
      try { q = parse(query); } catch (e) { throw { kind: 'invalid', message: e instanceof SearchError ? e.message : String(e) }; }
      const all = profiles.map(p => p.meta).filter(m => matches(q, m))
        .sort((a, c) => (a.last_opened_ms == null ? 1 : 0) - (c.last_opened_ms == null ? 1 : 0) || (c.last_opened_ms ?? 0) - (a.last_opened_ms ?? 0) || a.name.localeCompare(c.name));
      return { total: all.length, items: clone(all.slice(offset, offset + Math.max(1, limit))) };
    },
    async folders() {
      const m = new Map<string, number>();
      profiles.forEach(p => m.set(p.meta.folder, (m.get(p.meta.folder) ?? 0) + 1));
      return [...m.entries()].sort((a, c) => a[0].localeCompare(c[0]));
    },
    async getProfile(id) {
      need(); const p = prof(id); const v = profView(p);
      return clone({ meta: p.meta, persona: { device_id: v.device_id, os: v.os, user_agent: v.user_agent, screen: `${v.screen_width}x${v.screen_height}`, gpu: v.gpu_renderer, locale: v.locale, hardware_concurrency: v.hardware_concurrency, device_memory: v.device_memory }, health: p.health });
    },
    async createProfile(n) {
      need(); await wait(200);
      if (!n.name.trim()) throw { kind: 'invalid', message: 'name is required' };
      if (n.proxy_id) px(n.proxy_id);
      const seed = n.seed ? parseInt(n.seed.slice(-8), 16) : Math.floor(Math.random() * 2 ** 32);
      const d = pick(n.os ?? null, seed);
      const proxy = n.proxy_id ? px(n.proxy_id) : null;
      const meta: T.ProfileMeta = { id: mkId('n'), name: n.name, folder: n.folder ?? '', tags: n.tags ?? [], os: n.os ?? d.os[0], proxy_id: n.proxy_id ?? null, exit_ip: proxy?.ip ?? '', country: proxy?.cc ?? '', health: 0, status: 'stopped', color: n.color ?? '', notes: n.notes ?? '', created_ms: Date.now(), last_opened_ms: null };
      profiles.unshift({ meta, seed, device: d.id, geo: n.locale && n.locale !== 'en-US' ? 'ok' : proxy ? 'ok' : 'none', doh: 'cloudflare', health: null });
      return clone(meta);
    },
    async editProfile(id, e) {
      const p = prof(id);
      Object.assign(p.meta, Object.fromEntries(Object.entries(e).filter(([, v]) => v !== undefined && v !== null)));
      return clone(p.meta);
    },
    async deleteProfiles(ids) {
      let n = 0;
      for (const id of ids) { const i = profiles.findIndex(p => p.meta.id === id); if (i >= 0) { profiles.splice(i, 1); failed.delete(id); n++; } }
      return n;
    },
    async fingerprint(id) { need(); await wait(80); return profView(prof(id)); },
    async previewFingerprint(os, locale, seed) {
      if (!/^(0x)?[0-9a-f]{1,16}$/i.test(seed)) throw { kind: 'invalid', message: `seed '${seed}' is not a 64-bit hex value` };
      const s = parseInt(seed.slice(-8), 16);
      const d = pick(os, s);
      return view(os ?? d.os[0], d.id, s, locale ?? 'en-US', null);
    },
    async regenerateFingerprint(id, os) {
      need(); await wait(300); const p = prof(id);
      const seed = Math.floor(Math.random() * 2 ** 32); const d = pick(os ?? p.meta.os, seed);
      p.seed = seed; p.device = d.id; p.meta.os = os ?? p.meta.os; p.meta.health = 0; p.health = null;
      return clone(p.meta);
    },
    async listProxies() { return clone(proxies.map(p => p.view)); },
    async importProxies(text, def) {
      need(); await wait(150);
      const rows = parseList(text, def); const added: T.ProxyView[] = []; const errors: T.ImportResult['errors'] = [];
      for (const r of rows) {
        if (r.err) { errors.push({ line: r.line, message: r.err }); continue; }
        const v: T.ProxyView = { id: mkId('ipx'), scheme: r.scheme!, host: r.host!, port: r.port!, username: r.user ?? null, has_password: !!r.hasPassword, label: '', state: { state: 'unknown' }, display: r.user ? `${r.scheme}://${r.user}:***@${r.host}:${r.port}` : `${r.scheme}://${r.host}:${r.port}`, preset: null, checks: null };
        const keys = Object.keys(COUNTRIES);
        proxies.push({ view: v, cc: keys[hashStr(r.host!) % keys.length], ip: r.host!, latency: 40 + (hashStr(r.host!) % 90), kind: 'ok' });
        added.push(clone(v));
      }
      return { added, errors };
    },
    async previewPreset(preset) { return buildPreset(preset); },
    async addProxy(form, password) {
      need(); await wait(120);
      const f = await checkForm(form);
      if (password && !f.username) throw { kind: 'invalid', message: 'a password needs a username' };
      const v: T.ProxyView = { id: mkId('apx'), ...f, has_password: !!password, state: { state: 'unknown' }, display: '', checks: null };
      v.display = display(v);
      const keys = Object.keys(COUNTRIES);
      proxies.push({ view: v, cc: keys[hashStr(v.host) % keys.length], ip: /^\d+\.\d+\.\d+\.\d+$/.test(v.host) ? v.host : `198.51.100.${hashStr(v.host) % 250}`, latency: 40 + (hashStr(v.host) % 90), kind: 'ok' });
      return clone(v);
    },
    async editProxy(id, form, password) {
      need(); await wait(120); const x = px(id);
      const f = await checkForm(form);
      if (password && !f.username) throw { kind: 'invalid', message: 'a password needs a username' };
      const old = x.view;
      const hasPw = !f.username ? false : password === null ? old.has_password : password !== '';
      const changed = password !== null || old.scheme !== f.scheme || old.host !== f.host || old.port !== f.port || old.username !== f.username || hasPw !== old.has_password;
      x.view = { ...old, ...f, has_password: hasPw, state: changed ? { state: 'unknown' } : old.state, display: '', checks: changed ? null : old.checks };
      x.view.display = display(x.view);
      if (changed) profiles.forEach(p => { if (p.meta.proxy_id === id) p.health = null; });
      return clone(x.view);
    },
    async deleteProxy(id) {
      need(); const i = proxies.findIndex(p => p.view.id === id); if (i < 0) throw { kind: 'not_found', message: `proxy ${id}` };
      proxies.splice(i, 1); profiles.forEach(p => { if (p.meta.proxy_id === id) { p.meta.proxy_id = null; p.meta.exit_ip = ''; p.meta.country = ''; } });
    },
    async assignProxy(pid, proxyId) {
      const p = prof(pid); const shared = proxyId ? sharedWith(pid, proxyId) : [];
      const x = proxyId ? px(proxyId) : null;
      p.meta.proxy_id = proxyId; p.meta.exit_ip = x?.ip ?? ''; p.meta.country = x?.cc ?? ''; p.health = null;
      if (p.meta.status === 'blocked') p.meta.status = 'stopped';
      return { shared_with: shared };
    },
    async testProxy(id) {
      need(); const x = px(id); await wait(600);
      const t = Date.now();
      if (x.kind === 'offline') { x.view.state = { state: 'offline', checked_ms: t, reason: 'timeout' }; pushLog('proxy_failure', null, `proxy ${x.view.display} check failed: timed out`); }
      else { const base = x.latency ?? 60; x.view.state = { state: 'online', checked_ms: t, latency_ms: x.kind === 'slow' ? 380 + (t % 70) : Math.max(12, Math.round(base * (0.85 + (t % 30) / 100))) }; }
      return clone(x.view);
    },
    async inspectProxy(id, speed) {
      const v = await this.testProxy(id); const x = px(id);
      const t = Date.now();
      const skip = (reason: string) => ({ status: 'skipped' as const, reason });
      const old = x.view.checks;
      if (v.state.state !== 'online') {
        x.view.checks = { checked_ms: t, exit: skip('proxy offline'), udp: skip('proxy offline'), blacklist: skip('proxy offline'), speed: speed ? { checked_ms: t, result: skip('proxy offline') } : old?.speed ?? null };
        return clone(x.view);
      }
      await wait(500);
      const h = hashStr(x.view.host);
      const zones: [string, string][] = [['zen.spamhaus.org', 'Spamhaus ZEN'], ['bl.spamcop.net', 'SpamCop'], ['dnsbl.dronebl.org', 'DroneBL'], ['psbl.surriel.com', 'PSBL']];
      const blacklist: T.DnsblResult[] = zones.map(([zone, name], i) => i === 0
        ? { zone, name, state: 'unknown', reason: 'test entry 127.0.0.2: the list refuses queries from public resolvers (127.255.255.254)' }
        : x.kind === 'slow' && i === 2 ? { zone, name, state: 'listed', codes: ['127.0.0.9'] } : { zone, name, state: 'not_listed' });
      let sp = old?.speed ?? null;
      if (speed) { await wait(700); const mbps = Math.round(4000 / Math.max(20, x.latency ?? 60) * 100) / 100; sp = { checked_ms: Date.now(), result: { status: 'ok', result: { bytes: 2_000_000, millis: Math.round(16000 / mbps), mbps, complete: true } } }; }
      x.view.checks = {
        checked_ms: t,
        exit: { status: 'ok', result: { ip: x.ip, asn: 64496 + (h % 15), org: `Example Net ${String.fromCharCode(65 + (h % 26))}`, country: x.cc } },
        udp: { status: 'ok', result: x.view.scheme !== 'socks5' ? { support: 'not_socks5' } : h % 3 === 0 ? { support: 'supported' } : { support: 'unsupported', reply: 7 } },
        blacklist: { status: 'ok', result: blacklist },
        speed: sp,
      };
      return clone(x.view);
    },
    async geoPreview(ids) {
      need();
      if (geoip.state !== 'ready') throw { kind: 'unsupported', message: geoip.state === 'failed' ? `the GeoIP database is not usable: ${geoip.message}` : 'this build has no offline GeoIP database' };
      await wait(500);
      const geoText = (lat: number | null, lng: number | null) => lat == null || lng == null ? null : `${lat.toFixed(4)}, ${lng.toFixed(4)}`;
      return ids.map(id => {
        const p = prof(id);
        const plan: T.GeoPlan = { profile_id: id, name: p.meta.name, proxy_id: p.meta.proxy_id, exit_ip: null, location: null, changes: [], problem: null };
        const x = p.meta.proxy_id ? proxies.find(y => y.view.id === p.meta.proxy_id) : undefined;
        if (!x) { plan.problem = 'no proxy assigned'; return plan; }
        if (x.kind === 'offline') { plan.problem = 'exit IP not measured: timed out'; return plan; }
        plan.exit_ip = x.ip;
        const c = COUNTRIES[x.cc];
        if (!c) { plan.problem = `${x.ip} is not in the GeoIP database`; return plan; }
        plan.location = { country: x.cc, country_name: c.name, region: null, city: c.city, latitude: c.lat, longitude: c.lng, timezone: c.tz };
        const cur = profView(p);
        const next = profView({ ...p, geo: 'ok', lang: undefined });
        const fields: [T.GeoField, string | null, string, boolean][] = [
          ['country', cur.country, next.country!, false], ['timezone', cur.timezone, next.timezone!, false],
          ['geolocation', geoText(cur.latitude, cur.longitude), geoText(next.latitude, next.longitude)!, false],
          ['locale', cur.locale, next.locale, true], ['languages', cur.languages.join(', '), next.languages.join(', '), true],
          ['accept_language', cur.accept_language, next.accept_language, true],
        ];
        plan.changes = fields.filter(([, from, to]) => from !== to).map(([field, from, to, language]) => ({ field, from, to, language }));
        return plan;
      });
    },
    async geoApply(items) {
      need();
      if (geoip.state !== 'ready') throw { kind: 'unsupported', message: 'this build has no offline GeoIP database' };
      await wait(200);
      return items.map(it => {
        const p = prof(it.profile_id);
        const x = p.meta.proxy_id ? proxies.find(y => y.view.id === p.meta.proxy_id) : undefined;
        if (p.meta.status === 'running') return { profile_id: it.profile_id, changed: false, error: 'the profile is already running' };
        if (!x || x.ip !== it.exit_ip || !COUNTRIES[x.cc]) return { profile_id: it.profile_id, changed: false, error: `${it.exit_ip} is not in the GeoIP database` };
        const before = JSON.stringify(profView(p));
        const keep = profView(p).locale;
        p.geo = 'ok'; p.lang = it.languages ? undefined : keep;
        const changed = JSON.stringify(profView(p)) !== before;
        if (changed) { p.health = null; p.meta.health = 0; }
        p.meta.exit_ip = x.ip; p.meta.country = x.cc;
        if (p.meta.status === 'blocked') p.meta.status = 'stopped';
        return { profile_id: it.profile_id, changed, error: null };
      });
    },
    async launchProfile(id, confirmed = false) {
      need(); const p = prof(id);
      if (engineCheck.state === 'failed') throw { kind: 'engine_integrity', message: `the installed engine does not match its SHA256SUMS (${engineCheck.message}); reinstall Vanta` };
      if (p.meta.status === 'running') throw { kind: 'already_running' };
      const f = failed.get(id);
      if (!confirmed && f && f.n >= MAX_FAILED_LAUNCHES) throw { kind: 'confirm_required', failures: f.n, last_error: f.last };
      const reasons: { code: string; message: string }[] = [];
      const x = p.meta.proxy_id ? proxies.find(y => y.view.id === p.meta.proxy_id) : undefined;
      if (!x) reasons.push({ code: 'no_proxy', message: 'launch blocked: the profile has no proxy (Vanta never connects directly)' });
      else if (x.view.state.state === 'offline') reasons.push({ code: 'proxy_offline', message: 'launch blocked: proxy offline (timed out)' });
      const bad = profView(p).rules.filter(r => r.level === 'fail');
      if (bad.length) reasons.push({ code: 'rules_failed', message: `launch blocked: consistency rule ${bad.map(r => r.id).join(', ')} failed (${bad[0].message})` });
      if (p.health && p.health.score < 60) reasons.push({ code: 'health_too_low', message: `launch blocked: health score ${p.health.score} is below 60` });
      else if (!p.health && x && x.view.state.state !== 'offline') reasons.push({ code: 'health_missing', message: 'launch blocked: no health check for this engine and proxy yet; run one first' });
      if (reasons.length) {
        p.meta.status = 'blocked'; pushLog('launch_blocked', id, reasons.map(r => r.code).join(', ')); emitStatus([{ profile_id: id, status: 'blocked', exit_code: null }]);
        failed.set(id, { n: (f?.n ?? 0) + 1, last: 'launch blocked: ' + reasons.map(r => r.message.replace(/^launch blocked: /, '')).join('; ') });
        throw { kind: 'blocked', reasons };
      }
      await wait(900);
      p.meta.status = 'running'; p.meta.last_opened_ms = Date.now(); failed.delete(id);
      const port = 49152 + (hashStr(id + Date.now()) % 16000);
      pushLog('profile_launch', id, `engine ${ENGINE} pid ${3000 + (port % 5000)}, relay 127.0.0.1:${port}, proxy ${x!.view.display}`);
      emitStatus([{ profile_id: id, status: 'running', exit_code: null }]);
      return { profile_id: id, pid: 3000 + (port % 5000), relay_port: port, engine_version: ENGINE };
    },
    async stopProfile(id) {
      const p = prof(id); if (p.meta.status !== 'running') throw { kind: 'not_running' };
      await wait(300);
      p.meta.status = 'stopped'; pushLog('profile_stop', id, 'stopped by user'); emitStatus([{ profile_id: id, status: 'stopped', exit_code: null }]);
    },
    async runningProfiles() { return profiles.filter(p => p.meta.status === 'running').map(p => p.meta.id); },
    async runHealth(id) {
      need(); const p = prof(id);
      if (p.meta.status === 'running') throw { kind: 'already_running' };
      const x = p.meta.proxy_id ? proxies.find(y => y.view.id === p.meta.proxy_id) : undefined;
      if (!x) throw { kind: 'blocked', reasons: [{ code: 'no_proxy', message: 'launch blocked: the profile has no proxy (Vanta never connects directly)' }] };
      if (x.view.state.state === 'offline') { p.meta.status = 'blocked'; throw { kind: 'blocked', reasons: [{ code: 'proxy_offline', message: 'launch blocked: proxy offline (timed out)' }] }; }
      await wait(1500);
      const problems: T.CheckProblem[] = [{ id: 'H35', title: CHECKS[34].title, outcome: 'warn', message: 'One extra extension vs. most real devices with this GPU.' }];
      if (x.kind === 'slow') problems.push({ id: 'H06', title: CHECKS[5].title, outcome: 'warn', message: `Proxy answers but DNS through it takes ${x.latency} ms.` });
      if (PROXY_SEED.find(s => s[0] === x.view.label)?.[2] === 'Own server') problems.push({ id: 'H03', title: CHECKS[2].title, outcome: 'warn', message: 'Exit ASN belongs to a hosting network. Fine for QA, risky for accounts.' });
      const v = profView(p);
      if (v.rules.some(r => r.id === 'C018' && r.level === 'fail')) problems.unshift({ id: 'H05', title: CHECKS[4].title, outcome: 'fail', message: 'Timezone / location do not match the exit IP country.' });
      const sc = score(problems);
      const summary: T.HealthSummary = { profile_id: id, score: sc, blocked: sc < 60, failing: problems.filter(q => q.outcome === 'fail').map(q => q.id), engine: ENGINE, proxy_id: x.view.id, ts_ms: Date.now() };
      p.health = summary; p.meta.health = sc; if (p.meta.status === 'blocked' && sc >= 60) p.meta.status = 'stopped';
      pushLog('health_run', id, `score ${sc}${sc < 60 ? ' (blocks launch)' : ''}; failing: ${summary.failing.join(' ') || 'none'}`);
      return clone({ summary, problems });
    },
    async guardPolicy(id) { need(); return { kill_switch: 'fail_closed', webrtc: 'disable_non_proxied_udp', doh: clone(prof(id).doh) }; },
    async setDohProvider(id, doh) { need(); const p = prof(id); p.doh = doh; p.health = null; p.meta.health = 0; return { kill_switch: 'fail_closed', webrtc: 'disable_non_proxied_udp', doh: clone(doh) }; },
    async activityLog(q) {
      need();
      const all = log.filter(e => (!q.kinds?.length || q.kinds.includes(e.kind)) && (!q.profile || e.profile === q.profile) && (q.from_ms == null || e.ts_ms >= q.from_ms) && (q.to_ms == null || e.ts_ms < q.to_ms));
      const lim = q.limit || 100; const off = q.offset || 0;
      return { total: all.length, entries: clone(all.slice().reverse().slice(off, off + lim)) };
    },
    async getSettings() { return clone(settings); },
    async setSettings(s) {
      if (![0, 1, 5, 10, 15, 30, 60].includes(s.autolock_minutes)) throw { kind: 'invalid', message: 'auto-lock must be one of 0, 1, 5, 10, 15, 30, 60 minutes' };
      for (const [k, v] of [['IP echo URL', s.ip_echo_url], ['IP info URL', s.ip_info_url], ['Speed test URL', s.speed_test_url]] as const) {
        const problem = v == null ? null : echoUrlProblem(v);
        if (problem) throw { kind: 'invalid', message: `${k}: ${problem}` };
      }
      settings = clone(s); lastActive = Date.now(); return clone(settings);
    },
    async reportActivity() { lastActive = Date.now(); },
    async quit() { profiles.forEach(p => { if (p.meta.status === 'running') p.meta.status = 'stopped'; }); doLock('user'); },
    onStatus: cb => sub(listeners.status, cb),
    onLog: cb => sub(listeners.log, cb),
    onLocked: cb => sub(listeners.locked, cb),
    onCloseRequested: cb => sub(listeners.close, cb),
  };
  // Test hook: simulate the window close button.
  (b as Backend & { requestClose(): void }).requestClose = () => listeners.close.forEach(f => f({ running: profiles.filter(p => p.meta.status === 'running').length }));
  return b;
}
